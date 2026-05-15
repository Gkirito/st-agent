package anytls

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sync"
	"time"

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
	userpass map[[32]byte]int

	httpClient *http.Client

	cancel          context.CancelFunc
	remoteConfigURL string
}

func NewUserPool(remoteConfigURL string) *UserPool {
	return &UserPool{
		l:               zap.L().Named("user_pool"),
		users:           make(map[int]*User),
		userpass:        make(map[[32]byte]int),
		remoteConfigURL: remoteConfigURL,
	}
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
	up.userpass[sha256.Sum256([]byte(u.Password))] = u.ID
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
	user, ok := up.users[id]
	if !ok {
		return
	}
	delete(up.users, id)
	delete(up.userpass, sha256.Sum256([]byte(user.Password)))
}

func (up *UserPool) AuthenticateHash(hash [32]byte) (*User, bool) {
	up.RLock()
	defer up.RUnlock()
	uid, ok := up.userpass[hash]
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
				up.Lock()
				delete(up.userpass, sha256.Sum256([]byte(oldUser.Password)))
				oldUser.UpdateFromServer(newUser)
				up.userpass[sha256.Sum256([]byte(oldUser.Password))] = oldUser.ID
				oldUser.running = false
				up.Unlock()
			}
		}
		userM[newUser.ID] = struct{}{}
	}
	// remove user not in server
	for _, user := range up.GetAllUsers() {
		if _, ok := userM[user.ID]; !ok {
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
		defer ticker.Stop()
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
