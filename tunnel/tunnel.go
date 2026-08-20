package tunnel

import (
	"context"
	"sync"
	"time"

	"go.uber.org/atomic"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

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

	// gvisorStack is the userspace TCP/IP stack that owns the TCP
	// endpoints for connections flowing through this tunnel. The tunnel
	// holds a reference so it can call FindTransportEndpoint + Abort
	// on the endpoint that corresponds to a failed dial — that sends
	// a real RST to the kernel (with valid sequence numbers from the
	// endpoint's state machine), so the application sees ECONNREFUSED
	// instead of EOF.
	//
	// Set via SetStack after core.CreateStack returns the *stack.Stack.
	// nil means "no smart-error path available; fall back to graceful
	// close on dial failures" — same as before this feature was added.
	gvisorStack   *stack.Stack
	gvisorStackMu sync.RWMutex

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

// SetStack stores the gvisor userspace TCP/IP stack that owns the TCP
// endpoints for connections flowing through this tunnel. The tunnel
// uses it to look up the endpoint for a failed dial and call Abort(),
// which makes the endpoint emit a real RST to the kernel with valid
// sequence numbers — so the application sees ECONNREFUSED instead of
// EOF on the next read.
//
// Call this once after core.CreateStack returns the *stack.Stack and
// before any SYN reaches the tunnel. Idempotent; safe from any
// goroutine.
func (t *Tunnel) SetStack(s *stack.Stack) {
	t.gvisorStackMu.Lock()
	defer t.gvisorStackMu.Unlock()
	t.gvisorStack = s
}

func (t *Tunnel) getStack() *stack.Stack {
	t.gvisorStackMu.RLock()
	defer t.gvisorStackMu.RUnlock()
	return t.gvisorStack
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
