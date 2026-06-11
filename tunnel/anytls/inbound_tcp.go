package anytls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"runtime/debug"
	"strings"

	"anytls/proxy/padding"
	"anytls/proxy/session"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"go.uber.org/zap"
)

func handleTcpConnection(ctx context.Context, c net.Conn, tlsConfig *tls.Config, up *UserPool) {
	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("[BUG] anytls inbound panic", zap.Any("recover", r), zap.String("stack", string(debug.Stack())))
		}
	}()

	c = tls.Server(c, tlsConfig)
	defer c.Close()

	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(c)
	if err != nil {
		zap.L().Debug("anytls ReadOnceFrom failed", zap.Error(err))
		return
	}
	c = bufio.NewCachedConn(c, b)

	// Read 32 bytes auth hash
	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		zap.L().Debug("anytls read auth hash failed", zap.Error(err))
		return
	}

	// Convert to [32]byte for O(1) map lookup
	var authHash [32]byte
	copy(authHash[:], by)

	user, ok := AuthenticateHash(up, authHash)
	if !ok || !user.Enable {
		zap.L().Debug("anytls authentication failed or user disabled")
		return
	}

	// Read 2 bytes padding length
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		zap.L().Debug("anytls read padding length failed", zap.Error(err))
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			zap.L().Debug("anytls read padding failed", zap.Error(err))
			return
		}
	}

	sess := session.NewServerSession(c, func(stream *session.Stream) {
		defer func() {
			if r := recover(); r != nil {
				zap.L().Error("[BUG] anytls stream panic", zap.Any("recover", r), zap.String("stack", string(debug.Stack())))
			}
		}()
		defer stream.Close()

		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			zap.L().Debug("anytls ReadAddrPort failed", zap.Error(err))
			return
		}

		cc := newCountingConn(stream, &user.UploadTraffic, &user.DownloadTraffic)

		if strings.Contains(destination.String(), "udp-over-tcp.arpa") {
			proxyOutboundUoT(ctx, cc, destination)
		} else {
			proxyOutboundTCP(ctx, cc, destination)
		}
	}, &padding.DefaultPaddingFactory)
	sess.Run()
	sess.Close()
}
