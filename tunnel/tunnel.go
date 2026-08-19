package tunnel

import (
	"context"
	"io"
	"sync"
	"time"

	"go.uber.org/atomic"

	"github.com/101-beep/tun2socks/v2/core/adapter"
	"github.com/101-beep/tun2socks/v2/proxy"
	"github.com/101-beep/tun2socks/v2/tunnel/statistic"
)

const (
	// tcpConnectTimeout is the default timeout for TCP handshakes.
	tcpConnectTimeout = 5 * time.Second
	// tcpWaitTimeout implements a TCP half-close timeout.
	tcpWaitTimeout = 60 * time.Second
	// udpSessionTimeout is the default timeout for UDP sessions.
	udpSessionTimeout = 60 * time.Second
)

var _ adapter.TransportHandler = (*Tunnel)(nil)

type Tunnel struct {
	// Unbuffered TCP/UDP queues.
	tcpQueue chan adapter.TCPConn
	udpQueue chan adapter.UDPConn

	// UDP session timeout.
	udpTimeout *atomic.Duration

	// Internal proxy.Proxy for Tunnel.
	proxyMu sync.RWMutex
	proxy   proxy.Proxy

	// Where the Tunnel statistics are sent to.
	manager *statistic.Manager

	// tunWriter is the raw TUN device for injecting
	// TCP RST / ICMP Destination Unreachable packets back to the
	// kernel when a dial fails. Set via SetTUNWriter after
	// construction; can be nil for tunnels that don't need smart
	// error responses.
	//
	// We deliberately bypass gvisor's LinkEndpoint.WritePackets here
	// because that path requires the endpoint to be in StateStarted
	// and a couple of state fields line up; the tun2socks TUN device
	// is fine to use as a LinkEndpoint for normal traffic but rejects
	// direct WritePackets with "endpoint is in invalid state" from
	// our injection goroutine. Direct io.Writer.Write() goes straight
	// to the TUN fd and the kernel reads it as if it arrived from
	// the network — exactly what we want.
	tunWriter   io.Writer
	tunWriterMu sync.RWMutex

	procOnce   sync.Once
	procCancel context.CancelFunc
}

func New(proxy proxy.Proxy, manager *statistic.Manager) *Tunnel {
	return &Tunnel{
		tcpQueue:   make(chan adapter.TCPConn),
		udpQueue:   make(chan adapter.UDPConn),
		udpTimeout: atomic.NewDuration(udpSessionTimeout),
		proxy:      proxy,
		manager:    manager,
		procCancel: func() { /* nop */ },
	}
}

// SetTUNWriter stores the raw TUN writer so the tunnel can inject
// smart error packets (TCP RST for connection-refused, ICMP Destination
// Unreachable for host-unreachable) back to the kernel when a dial
// through the proxy fails. Idempotent; safe to call from any goroutine.
//
// The TUN device (from github.com/101-beep/tun2socks/v2/core/device/tun)
// implements io.Writer via Write([]byte) (int, error), so any reference
// to it (e.g. the *tun.TUN returned by tun.Open) can be passed here.
func (t *Tunnel) SetTUNWriter(w io.Writer) {
	t.tunWriterMu.Lock()
	defer t.tunWriterMu.Unlock()
	t.tunWriter = w
}

func (t *Tunnel) getTUNWriter() io.Writer {
	t.tunWriterMu.RLock()
	defer t.tunWriterMu.RUnlock()
	return t.tunWriter
}

// TCPIn return fan-in TCP queue.
func (t *Tunnel) TCPIn() chan<- adapter.TCPConn {
	return t.tcpQueue
}

// UDPIn return fan-in UDP queue.
func (t *Tunnel) UDPIn() chan<- adapter.UDPConn {
	return t.udpQueue
}

func (t *Tunnel) HandleTCP(conn adapter.TCPConn) {
	t.TCPIn() <- conn
}

func (t *Tunnel) HandleUDP(conn adapter.UDPConn) {
	t.UDPIn() <- conn
}

func (t *Tunnel) process(ctx context.Context) {
	for {
		select {
		case conn := <-t.tcpQueue:
			go t.handleTCPConn(conn)
		case conn := <-t.udpQueue:
			go t.handleUDPConn(conn)
		case <-ctx.Done():
			return
		}
	}
}

// ProcessAsync can be safely called multiple times, but will only be effective once.
func (t *Tunnel) ProcessAsync() {
	t.procOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		t.procCancel = cancel
		go t.process(ctx)
	})
}

// Close closes the Tunnel and releases its resources.
func (t *Tunnel) Close() {
	t.procCancel()
}

func (t *Tunnel) Proxy() proxy.Proxy {
	t.proxyMu.RLock()
	p := t.proxy
	t.proxyMu.RUnlock()
	return p
}

func (t *Tunnel) SetProxy(proxy proxy.Proxy) {
	t.proxyMu.Lock()
	t.proxy = proxy
	t.proxyMu.Unlock()
}

func (t *Tunnel) SetUDPTimeout(timeout time.Duration) {
	t.udpTimeout.Store(timeout)
}
