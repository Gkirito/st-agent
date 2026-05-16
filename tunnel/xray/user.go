package xray

import (
	"context"
	"strconv"

	"github.com/gkirito/st-agent/tunnel/common"
	proxy "github.com/xtls/xray-core/app/proxyman/command"
	stats "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type User = common.User
type UserTraffic = common.UserTraffic
type SyncTrafficReq = common.SyncTrafficReq
type SyncUserConfigsResp = common.SyncUserConfigsResp
type UserPool = common.UserPool

func NewUserPool(grpcEndPoint, remoteConfigURL, metricURL string, proxyTags []string) *UserPool {
	var proxyClient proxy.HandlerServiceClient
	var statsClient stats.StatsServiceClient
	var br *bandwidthRecorder
	if metricURL != "" {
		br = NewBandwidthRecorder(metricURL)
	}
	return common.NewUserPool(common.PoolConfig{
		RemoteConfigURL: remoteConfigURL,
		PasswordKey:     nil,
		Init: func(ctx context.Context) error {
			conn, err := grpc.NewClient(grpcEndPoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return err
			}
			proxyClient = proxy.NewHandlerServiceClient(conn)
			statsClient = stats.NewStatsServiceClient(conn)
			return nil
		},
		IterTags: func() []string { return proxyTags },
		FetchTraffic: func(ctx context.Context, getUser func(int) (*common.User, bool)) error {
			return fetchXrayTraffic(ctx, statsClient, getUser, proxyClient, proxyTags)
		},
		OnUserAdd: func(ctx context.Context, user *common.User) error {
			tag := proxyTags[0]
			return AddInboundUser(ctx, proxyClient, tag, user)
		},
		OnUserUpdate: func(ctx context.Context, oldUser, newUser *common.User) {
			tag := proxyTags[0]
			if oldUser.IsRunning() {
				RemoveInboundUser(ctx, proxyClient, tag, oldUser)
			}
			if newUser.Enable {
				AddInboundUser(ctx, proxyClient, tag, newUser)
			}
		},
		OnUserRemove: func(ctx context.Context, user *common.User) error {
			tag := proxyTags[0]
			return RemoveInboundUser(ctx, proxyClient, tag, user)
		},
		RecordBandwidth: func(ctx context.Context) (int64, int64, error) {
			if br == nil {
				return 0, 0, nil
			}
			up, down, err := br.RecordOnce(ctx)
			return int64(up), int64(down), err
		},
	})
}

func ToXrayUser(u *User) *protocol.User {
	var account *serial.TypedMessage
	switch u.Protocol {
	case ProtocolTrojan:
		account = serial.ToTypedMessage(&trojan.Account{Password: u.Password})
	case ProtocolSS:
		account = serial.ToTypedMessage(&shadowsocks.Account{CipherType: mappingCipher(u.Method), Password: u.Password})
	default:
		zap.S().DPanicf("unknown protocol %s", u.Protocol)
		return nil
	}
	return &protocol.User{Level: uint32(u.Level), Email: u.GetEmail(), Account: account}
}

func fetchXrayTraffic(ctx context.Context, statsClient stats.StatsServiceClient, getUser func(int) (*common.User, bool), proxyClient proxy.HandlerServiceClient, proxyTags []string) error {
	// V2ray stats names are formatted as:
	// upload: "user>>>" + user.Email + ">>>traffic>>>uplink"
	// download: "user>>>" + user.Email + ">>>traffic>>>downlink"
	resp, err := statsClient.QueryStats(ctx, &stats.QueryStatsRequest{Pattern: "user>>>", Reset_: true})
	if err != nil {
		return err
	}

	for _, stat := range resp.Stat {
		userIDStr, trafficType := getEmailAndTrafficType(stat.Name)
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			return err
		}
		user, found := getUser(userID)
		if !found {
			zap.S().Named("user_pool").Warnf(
				"user in xray not found in user pool this user maybe out of traffic, user id: %d, leak traffic: %d",
				userID, stat.Value)
			fakeUser := &User{ID: userID}
			if err := RemoveInboundUser(ctx, proxyClient, proxyTags[0], fakeUser); err != nil {
				zap.L().Named("user_pool").Warn("tring remove leak user failed, user id: %d err: %s",
					zap.Int("user_id", userID), zap.Error(err))
			}
			continue
		}
		// Xray only records inbound traffic, so double it to account for outbound traffic.
		switch trafficType {
		case "uplink":
			user.UploadTraffic = stat.Value * 2
		case "downlink":
			user.DownloadTraffic = stat.Value * 2
		}
	}
	return nil
}
