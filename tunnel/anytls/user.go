package anytls

import (
	"crypto/sha256"

	"github.com/gkirito/st-agent/tunnel/common"
)

type User = common.User
type UserTraffic = common.UserTraffic
type SyncTrafficReq = common.SyncTrafficReq
type SyncUserConfigsResp = common.SyncUserConfigsResp
type UserPool = common.UserPool

func NewUserPool(remoteConfigURL string) *UserPool {
	return common.NewUserPool(common.PoolConfig{
		RemoteConfigURL: remoteConfigURL,
		PasswordKey: func(password string) any {
			return sha256.Sum256([]byte(password))
		},
	})
}

func AuthenticateHash(up *UserPool, hash [32]byte) (*User, bool) {
	return up.GetUserByKey(hash)
}
