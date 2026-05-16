package hysteria

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gkirito/st-agent/tunnel/common"
	"go.uber.org/zap"
)

type User = common.User
type UserTraffic = common.UserTraffic
type SyncTrafficReq = common.SyncTrafficReq
type SyncUserConfigsResp = common.SyncUserConfigsResp
type UserPool = common.UserPool

type traffic struct {
	Tx int64 `json:"tx"`
	Rx int64 `json:"rx"`
}

func NewUserPool(hysteriaEndpoint, remoteConfigURL, metricURL, hyEpSecret string) *UserPool {
	var br *bandwidthRecorder
	if metricURL != "" {
		br = NewBandwidthRecorder(metricURL)
	}
	return common.NewUserPool(common.PoolConfig{
		RemoteConfigURL: remoteConfigURL,
		PasswordKey:     func(password string) any { return password },
		FetchTraffic: func(ctx context.Context, getUser func(int) (*common.User, bool)) error {
			return fetchHysteriaTraffic(ctx, getUser, hysteriaEndpoint, hyEpSecret)
		},
		OnUserUpdate: func(ctx context.Context, oldUser, newUser *common.User) {
			if oldUser.IsRunning() {
				if err := kickUser(ctx, hysteriaEndpoint, hyEpSecret, oldUser.ID); err != nil {
					zap.L().Named("user_pool").Warn("kick updated hysteria user failed",
						zap.Int("user_id", oldUser.ID), zap.Error(err))
				}
				oldUser.SetRunning(false)
			}
		},
		OnUserRemove: func(ctx context.Context, user *common.User) error {
			return kickUser(ctx, hysteriaEndpoint, hyEpSecret, user.ID)
		},
		RecordBandwidth: func(ctx context.Context) (int64, int64, error) {
			if br == nil {
				return 0, 0, nil
			}
			if _, _, err := br.RecordOnce(ctx); err != nil {
				return 0, 0, err
			}
			return int64(br.GetUploadBandwidth()), int64(br.GetDownloadBandwidth()), nil
		},
	})
}

func GetUserByPass(up *UserPool, password string) (*User, bool) {
	return up.GetUserByKey(password)
}

func fetchHysteriaTraffic(ctx context.Context, getUser func(int) (*common.User, bool), host, secret string) error {
	resp, err := getTraffic(ctx, host, secret)
	if err != nil {
		return err
	}

	l := zap.L().Named("user_pool")
	for userIDStr, traffic := range resp {
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			return err
		}
		user, found := getUser(userID)
		if !found {
			l.Sugar().Warnf(
				"user in xray not found in user pool this user maybe out of traffic, user id: %d, leak traffic: %d",
				userID, traffic.Rx+traffic.Tx)
			if err := kickUser(ctx, host, secret, userID); err != nil {
				l.Warn("tring remove leak user failed, user id: %d err: %s",
					zap.Int("user_id", userID), zap.Error(err))
			}
			continue
		}
		user.UploadTraffic = traffic.Tx
		user.DownloadTraffic = traffic.Rx
	}
	return nil
}

type httpError struct {
	statusCode int
	message    json.RawMessage
}

func (he *httpError) Error() string {
	if he == nil {
		return ""
	}
	msg := strings.TrimSpace(string(he.message))
	if msg == "" {
		return fmt.Sprintf("http error: status %d", he.statusCode)
	}
	return fmt.Sprintf("http error: status %d, message: %s", he.statusCode, msg)
}

func getTraffic(ctx context.Context, host, secret string) (map[string]*traffic, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/traffic?clear=1", nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", " "+secret)
	r.Header.Set("Content-Type", "application/json")
	resp, err := hysteriaHTTPClient().Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decode := json.NewDecoder(resp.Body)
	if resp.StatusCode >= 300 {
		var errBody json.RawMessage
		_ = decode.Decode(&errBody)
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    errBody,
		}
	}
	result := make(map[string]*traffic)
	if err := decode.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func kickUser(ctx context.Context, host, secret string, userIDs ...int) error {
	idStr := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		idStr = append(idStr, strconv.Itoa(id))
	}
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(idStr); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+host+"/kick", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", " "+secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hysteriaHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	if resp.StatusCode >= 300 {
		var errBody json.RawMessage
		_ = decoder.Decode(&errBody)
		return &httpError{
			statusCode: resp.StatusCode,
			message:    errBody,
		}
	}
	return nil
}

func hysteriaHTTPClient() *http.Client {
	return &http.Client{Timeout: time.Second * 10}
}
