package hysteria

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type authRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   int64  `json:"tx"`
}

type authResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
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
		user, ok := GetUserByPass(userPool, req.Auth)
		if !ok {
			writeBadRequest(w)
			return
		}
		userPool.Lock()
		user.SetRunning(true)
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
