package common

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

type PoolConfig struct {
	RemoteConfigURL string

	// FetchTraffic fetches per-user traffic from the protocol-specific source.
	// Called with the pool read-locked. Use getUser to look up users by ID.
	// Must update user.UploadTraffic/DownloadTraffic directly.
	FetchTraffic func(ctx context.Context, getUser func(int) (*User, bool)) error

	// OnUserAdd is called after a new user is created from remote config.
	// Return error to abort the sync cycle.
	OnUserAdd func(ctx context.Context, user *User) error

	// OnUserUpdate is called when an existing user's config has changed.
	// Called with the pool lock held.
	OnUserUpdate func(ctx context.Context, oldUser, newUser *User)

	// OnUserRemove is called before removing a user not present in remote config.
	// Return error to abort the sync cycle.
	OnUserRemove func(ctx context.Context, user *User) error

	// RecordBandwidth optionally reports server-wide bandwidth.
	// Returns upload bytes/sec, download bytes/sec, or error.
	RecordBandwidth func(ctx context.Context) (upload, download int64, err error)

	// Init is called once during Start(), before the sync loop begins.
	// Use it to establish connections (gRPC, etc.).
	Init func(ctx context.Context) error

	// PasswordKey computes the lookup key for the password map.
	// Return nil to skip password map maintenance (xray pattern).
	// Examples: func(p string) any { return p } for hysteria
	//           func(p string) any { h := sha256.Sum256([]byte(p)); return h } for anytls
	PasswordKey func(password string) any

	// IterTags returns tags to iterate sync over. nil means single iteration.
	// Example: xray returns []string{"tag1", "tag2"} for per-tag sync loops.
	IterTags func() []string
}

type UserPool struct {
	cfg PoolConfig
	l   *zap.Logger
	sync.RWMutex

	users    map[int]*User
	userpass map[any]int

	httpClient *http.Client
	cancel     context.CancelFunc
}

func NewUserPool(cfg PoolConfig) *UserPool {
	up := &UserPool{
		cfg:   cfg,
		l:     zap.L().Named("user_pool"),
		users: make(map[int]*User),
	}
	if cfg.PasswordKey != nil {
		up.userpass = make(map[any]int)
	}
	return up
}

func (up *UserPool) CreateUser(userId, level int, password, method, protocol string, enable bool) *User {
	up.Lock()
	defer up.Unlock()
	u := &User{
		ID:       userId,
		Password: password,
		Level:    level,
		Enable:   enable,
		Method:   method,
		Protocol: protocol,
	}
	up.users[u.ID] = u
	if up.cfg.PasswordKey != nil {
		up.userpass[up.cfg.PasswordKey(u.Password)] = u.ID
	}
	return u
}

func (up *UserPool) GetUser(id int) (*User, bool) {
	up.RLock()
	defer up.RUnlock()
	user, ok := up.users[id]
	return user, ok
}

func (up *UserPool) GetUserByKey(key any) (*User, bool) {
	up.RLock()
	defer up.RUnlock()
	uid, ok := up.userpass[key]
	if !ok {
		return nil, false
	}
	user, ok := up.users[uid]
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
	if up.cfg.PasswordKey != nil {
		delete(up.userpass, up.cfg.PasswordKey(user.Password))
	}
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
	if up.cfg.FetchTraffic != nil {
		if err := up.cfg.FetchTraffic(ctx, up.GetUser); err != nil {
			return err
		}
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

	if up.cfg.RecordBandwidth != nil {
		ub, db, err := up.cfg.RecordBandwidth(ctx)
		if err != nil {
			return err
		}
		req.UploadBandwidth = ub
		req.DownloadBandwidth = db
	}

	if err := PostJSON(up.httpClient, up.cfg.RemoteConfigURL, req); err != nil {
		return err
	}
	up.l.Sugar().Infof("Call syncTrafficToServer ONLINE USER COUNT: %d", len(tfs))
	return nil
}

func (up *UserPool) syncUserConfigsFromServer(ctx context.Context) error {
	resp := SyncUserConfigsResp{}
	if err := GetJSON(up.httpClient, up.cfg.RemoteConfigURL, &resp); err != nil {
		return err
	}
	userM := make(map[int]struct{})
	for _, newUser := range resp.Users {
		oldUser, found := up.GetUser(newUser.ID)
		if !found {
			_ = up.CreateUser(
				newUser.ID, newUser.Level, newUser.Password, newUser.Method, newUser.Protocol, newUser.Enable)
			if up.cfg.OnUserAdd != nil {
				if err := up.cfg.OnUserAdd(ctx, up.users[newUser.ID]); err != nil {
					return err
				}
			}
		} else if !oldUser.Equal(newUser) {
			oldPass := oldUser.Password
			oldUser.UpdateFromServer(newUser)
			if up.cfg.PasswordKey != nil && oldPass != newUser.Password {
				up.Lock()
				delete(up.userpass, up.cfg.PasswordKey(oldPass))
				up.userpass[up.cfg.PasswordKey(oldUser.Password)] = oldUser.ID
				up.Unlock()
			}
			if up.cfg.OnUserUpdate != nil {
				up.cfg.OnUserUpdate(ctx, oldUser, newUser)
			}
		}
		userM[newUser.ID] = struct{}{}
	}
	for _, user := range up.GetAllUsers() {
		if _, ok := userM[user.ID]; !ok {
			if up.cfg.OnUserRemove != nil {
				if err := up.cfg.OnUserRemove(ctx, user); err != nil {
					return err
				}
			}
			up.RemoveUser(user.ID)
		}
	}
	return nil
}

func (up *UserPool) Start(ctx context.Context) error {
	up.httpClient = &http.Client{Timeout: time.Second * 10}

	if up.cfg.Init != nil {
		if err := up.cfg.Init(ctx); err != nil {
			return err
		}
	}

	tags := []string{""}
	if up.cfg.IterTags != nil {
		tags = up.cfg.IterTags()
	}

	syncOnce := func() error {
		for range tags {
			if err := up.syncUserConfigsFromServer(ctx); err != nil {
				up.l.Sugar().Errorf("Sync User Configs From Server Error: %v", err)
				return err
			}
			if err := up.syncTrafficToServer(ctx); err != nil {
				up.l.Sugar().Errorf("Sync Traffic From Server Error: %v", err)
				return err
			}
		}
		return nil
	}

	if err := syncOnce(); err != nil {
		return err
	}

	ctx2, cancel := context.WithCancel(ctx)
	up.cancel = cancel
	go func() {
		ticker := time.NewTicker(time.Second * 60)
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
