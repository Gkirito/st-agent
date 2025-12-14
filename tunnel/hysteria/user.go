package hysteria

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gkirito/st-agent/tool/bytes"
	"go.uber.org/zap"
)

type User struct {
	running bool

	ID       int    `json:"user_id"`
	Method   string `json:"method"`
	Password string `json:"password"`

	Level           int   `json:"level"`
	Enable          bool  `json:"enable"`
	UploadTraffic   int64 `json:"upload_traffic"`
	DownloadTraffic int64 `json:"download_traffic"`

	Protocol string `json:"protocol"`
}

type UserTraffic struct {
	ID              int      `json:"user_id"`
	UploadTraffic   int64    `json:"upload_traffic"`
	DownloadTraffic int64    `json:"download_traffic"`
	IPList          []string `json:"ip_list"`
	TcpCount        int64    `json:"tcp_conn_num"`
}

type SyncTrafficReq struct {
	Data              []*UserTraffic `json:"data"`
	UploadBandwidth   int64          `json:"upload_bandwidth"`
	DownloadBandwidth int64          `json:"download_bandwidth"`
}

func (s *SyncTrafficReq) GetTotalTraffic() int64 {
	var total int64
	for _, u := range s.Data {
		total += u.UploadTraffic + u.DownloadTraffic
	}
	return total
}

type SyncUserConfigsResp struct {
	Users []*User `json:"users"`
}

// NOTE we use user id as email
func (u *User) GetEmail() string {
	return fmt.Sprintf("%d", u.ID)
}

func (u *User) ResetTraffic() {
	u.DownloadTraffic = 0
	u.UploadTraffic = 0
}

func (u *User) GenTraffic() *UserTraffic {
	return &UserTraffic{
		ID:              u.ID,
		UploadTraffic:   u.UploadTraffic,
		DownloadTraffic: u.DownloadTraffic,
		IPList:          []string{},
		TcpCount:        0,
	}
}

func (u *User) UpdateFromServer(serverSideUser *User) {
	u.Method = serverSideUser.Method
	u.Enable = serverSideUser.Enable
	u.Password = serverSideUser.Password
}

func (u *User) Equal(new *User) bool {
	return u.Method == new.Method && u.Enable == new.Enable && u.Password == new.Password
}

type UserPool struct {
	l *zap.Logger
	sync.RWMutex
	// map key : ID
	users    map[int]*User
	userpass map[string]int

	httpClient *http.Client

	br *bandwidthRecorder

	cancel           context.CancelFunc
	hysteriaEndpoint string
	hyEpSecret       string
	remoteConfigURL  string
}

func NewUserPool(hysteriaEndpoint, remoteConfigURL, metricURL, hyEpSecret string) *UserPool {
	up := &UserPool{
		l:                zap.L().Named("user_pool"),
		users:            make(map[int]*User),
		userpass:         make(map[string]int),
		hyEpSecret:       hyEpSecret,
		hysteriaEndpoint: hysteriaEndpoint,
		remoteConfigURL:  remoteConfigURL,
	}
	if metricURL != "" {
		up.br = NewBandwidthRecorder(metricURL)
	}
	return up
}

func (up *UserPool) CreateUser(userId, level int, password, method, protocol string, enable bool) *User {
	up.Lock()
	defer up.Unlock()
	u := &User{
		running:  false,
		ID:       userId,
		Password: password,
		Level:    level,
		Enable:   enable,
		Method:   method,
		Protocol: protocol,
	}
	up.users[u.ID] = u
	up.userpass[u.Password] = u.ID
	return u
}

func (up *UserPool) GetUser(id int) (*User, bool) {
	up.RLock()
	defer up.RUnlock()
	user, ok := up.users[id]
	return user, ok
}

func (up *UserPool) RemoveUser(id int) {
	up.Lock()
	defer up.Unlock()
	user, ok := up.GetUser(id)
	if !ok {
		return
	}
	delete(up.users, id)
	delete(up.userpass, user.Password)
}

func (up *UserPool) GetUserByPass(password string) (*User, bool) {
	up.RLock()
	defer up.RUnlock()
	uid, ok := up.userpass[password]
	if !ok {
		return nil, false
	}
	user, ok := up.users[uid]
	return user, ok
}

func (up *UserPool) GetAllUsers() []*User {
	up.RLock()
	defer up.RUnlock()

	users := make([]*User, 0, len(up.users))
	for _, user := range up.users {
		users = append(users, user)
	}
	return users
}

func (up *UserPool) syncTrafficToServer(ctx context.Context) error {
	resp, err := getTraffic(ctx, up.httpClient, up.hysteriaEndpoint, up.hyEpSecret)
	if err != nil {
		return err
	}

	for userIDStr, traffic := range resp {
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			return err
		}
		user, found := up.GetUser(userID)
		if !found {
			up.l.Sugar().Warnf(
				"user in xray not found in user pool this user maybe out of traffic, user id: %d, leak traffic: %d",
				userID, traffic.Rx+traffic.Tx)
			if err := kick(ctx, up.httpClient, up.hysteriaEndpoint, up.hyEpSecret, userID); err != nil {
				up.l.Warn("tring remove leak user failed, user id: %d err: %s",
					zap.Int("user_id", userID), zap.Error(err))
			}
			continue
		}
		user.UploadTraffic = traffic.Tx
		user.DownloadTraffic = traffic.Rx
	}

	tfs := make([]*UserTraffic, 0, len(up.users))
	for _, user := range up.GetAllUsers() {
		tf := user.DownloadTraffic + user.UploadTraffic
		if tf > 0 {
			up.l.Sugar().Infof("User: %v Now Used Total Traffic: %v", user.ID, tf)
			tfs = append(tfs, user.GenTraffic())
			user.ResetTraffic()
		}
	}
	req := &SyncTrafficReq{Data: tfs}
	if up.br != nil {
		// record bandwidth
		uploadIncr, downloadIncr, err := up.br.RecordOnce(ctx)
		if err != nil {
			return err
		}

		ub := up.br.GetUploadBandwidth()
		req.UploadBandwidth = int64(ub)
		db := up.br.GetDownloadBandwidth()
		req.DownloadBandwidth = int64(db)
		up.l.Sugar().Debug(
			"Upload Bandwidth :", bytes.PrettyByteSize(ub),
			"Download Bandwidth :", bytes.PrettyByteSize(db),
			"Total Bandwidth :", bytes.PrettyByteSize(ub+db),
			"Total Increment By BR", bytes.PrettyByteSize(uploadIncr+downloadIncr),
			"Total Increment By Xray :", bytes.PrettyByteSize(float64(req.GetTotalTraffic())),
		)
	}
	if err := postJson(up.httpClient, up.remoteConfigURL, req); err != nil {
		return err
	}
	up.l.Sugar().Infof("Call syncTrafficToServer ONLINE USER COUNT: %d", len(tfs))
	return nil
}

func (up *UserPool) syncUserConfigsFromServer(ctx context.Context) error {
	resp := SyncUserConfigsResp{}
	if err := getJson(up.httpClient, up.remoteConfigURL, &resp); err != nil {
		return err
	}
	userM := make(map[int]struct{})
	for _, newUser := range resp.Users {
		oldUser, found := up.GetUser(newUser.ID)
		if !found {
			_ = up.CreateUser(
				newUser.ID, newUser.Level, newUser.Password, newUser.Method, newUser.Protocol, newUser.Enable)
		} else {
			// update user configs
			if !oldUser.Equal(newUser) {
				oldUser.UpdateFromServer(newUser)
				if oldUser.running {
					if err := kick(ctx, up.httpClient, up.hysteriaEndpoint, up.hyEpSecret, oldUser.ID); err != nil {
						return err
					}
					oldUser.running = false
				}
			}
		}
		userM[newUser.ID] = struct{}{}
	}
	// remove user not in server
	for _, user := range up.GetAllUsers() {
		if _, ok := userM[user.ID]; !ok {
			if err := kick(ctx, up.httpClient, up.hysteriaEndpoint, up.hyEpSecret, user.ID); err != nil {
				return err
			}
			up.RemoveUser(user.ID)
		}
	}
	return nil
}

func (up *UserPool) Start(ctx context.Context) error {
	up.httpClient = &http.Client{Timeout: time.Second * 10}

	syncOnce := func() error {
		if err := up.syncUserConfigsFromServer(ctx); err != nil {
			up.l.Sugar().Errorf("Sync User Configs From Server Error: %v", err)
			return err
		}
		if err := up.syncTrafficToServer(ctx); err != nil {
			up.l.Sugar().Errorf("Sync Traffic From Server Error: %v", err)
			return err
		}
		return nil
	}
	if err := syncOnce(); err != nil {
		return err
	}

	ctx2, cancel := context.WithCancel(ctx)
	up.cancel = cancel
	go func() {
		ticker := time.NewTicker(time.Second * SyncTime)
		for {
			select {
			case <-ctx2.Done():
				return
			case <-ticker.C:
				if err := syncOnce(); err != nil {
					up.l.Error("Sync User Configs From Server Error: %v", zap.Error(err))
				}
			}
		}
	}()
	return nil
}

func (up *UserPool) Stop() {
	if up.cancel != nil {
		up.cancel()
	}
}
