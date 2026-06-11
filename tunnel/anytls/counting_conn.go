package anytls

import (
	"net"
	"sync/atomic"
)

type countingConn struct {
	net.Conn
	upload   *int64
	download *int64
}

func newCountingConn(conn net.Conn, upload, download *int64) *countingConn {
	return &countingConn{
		Conn:     conn,
		upload:   upload,
		download: download,
	}
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(c.download, int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(c.upload, int64(n))
	return n, err
}

// HandshakeSuccess forwards the call to the underlying conn if it supports it.
// This allows N.ReportHandshakeSuccess to work through the counting wrapper.
func (c *countingConn) HandshakeSuccess() error {
	if hs, ok := c.Conn.(interface{ HandshakeSuccess() error }); ok {
		return hs.HandshakeSuccess()
	}
	return nil
}

// HandshakeFailure forwards the call to the underlying conn if it supports it.
// This allows N.ReportHandshakeFailure to work through the counting wrapper.
func (c *countingConn) HandshakeFailure(err error) error {
	if hs, ok := c.Conn.(interface{ HandshakeFailure(error) error }); ok {
		return hs.HandshakeFailure(err)
	}
	return nil
}
