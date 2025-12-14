package hysteria

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type traffic struct {
	Tx int64 `json:"tx"`
	Rx int64 `json:"rx"`
}

type authRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   int64  `json:"tx"`
}

type authResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
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

func getTraffic(ctx context.Context, c *http.Client, host, secret string) (map[string]*traffic, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/traffic?clear=1", nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", " "+secret)
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(r)
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
	err = decode.Decode(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func kick(ctx context.Context, c *http.Client, host, secret string, userIDs ...int) error {
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
	resp, err := c.Do(req)
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

func NewHyServer(host string, port int, userPool *UserPool) (*http.Server, error) {
	if userPool == nil {
		return nil, fmt.Errorf("userPool is nil")
	}
	writeBadRequest := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(authResponse{OK: false})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeBadRequest(w)
			return
		}
		defer r.Body.Close()
		var req authRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w)
			return
		}
		if strings.TrimSpace(req.Auth) == "" {
			writeBadRequest(w)
			return
		}
		user, ok := userPool.GetUserByPass(req.Auth)
		if !ok {
			writeBadRequest(w)
			return
		}
		userPool.Lock()
		user.running = true
		userPool.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(authResponse{
			OK: true,
			ID: strconv.Itoa(user.ID),
		})
	})
	addr := fmt.Sprintf("%s:%d", host, port)
	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}, nil
}
