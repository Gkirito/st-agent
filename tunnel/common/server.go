package common

import "context"

type TunnelServer interface {
	Name() string
	Setup() error
	Start(ctx context.Context) error
	Stop()
	Reload() error
}
