package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/101-beep/tun2socks/v2/buffer"
	"github.com/101-beep/tun2socks/v2/core/adapter"
	"github.com/101-beep/tun2socks/v2/log"
	M "github.com/101-beep/tun2socks/v2/metadata"
	httpproxy "github.com/101-beep/tun2socks/v2/proxy/http"
	"github.com/101-beep/tun2socks/v2/transport/socks5"
	"github.com/101-beep/tun2socks/v2/tunnel/statistic"
)

func (t *Tunnel) handleTCPConn(originConn adapter.TCPConn) {
	// responded tracks whether injectSmartError already aborted the
	// gvisor endpoint (which emits a RST to the kernel). When true,
	// we skip the deferred originConn.Close() — otherwise gvisor's
	// graceful close would race our RST and the application might
	// see EOF instead of ECONNREFUSED.
	responded := false
	defer func() {
		if !responded {
			originConn.Close()
		}
	}()

	id := originConn.ID()
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   parseTCPIPAddress(id.RemoteAddress),
		SrcPort: id.RemotePort,
		DstIP:   parseTCPIPAddress(id.LocalAddress),
		DstPort: id.LocalPort,
	}

	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	remoteConn, err := t.Proxy().DialContext(ctx, metadata)
	if err != nil {
		log.Warnf("[TCP] dial %s: %v", metadata.DestinationAddress(), err)
		// Smart error translation: instead of letting Close() send
		// a bare FIN (which apps read as "Unknown SSH Version" or
		// similar false positive), abort the gvisor endpoint that
		// corresponds to this connection. Abort() calls
		// resetConnectionLocked, which emits a TCP RST with valid
		// sequence numbers drawn from the endpoint's own state
		// machine — so the kernel socket receives the RST, the
		// application's read() returns ECONNREFUSED, and tools like
		// nxc report the right errno.
		if t.injectSmartError(metadata, id, err) {
			responded = true
		}
		return
	}
	metadata.MidIP, metadata.MidPort = parseNetAddr(remoteConn.LocalAddr())

	remoteConn = statistic.NewTCPTracker(remoteConn, metadata, t.manager)
	defer remoteConn.Close()

	log.Infof("[TCP] %s <-> %s", metadata.SourceAddress(), metadata.DestinationAddress())
	pipe(originConn, remoteConn)
}

// injectSmartError translates a proxy-level dial failure into the
// appropriate kernel-level response by aborting the gvisor TCP endpoint
// that represents this connection. The endpoint's state machine then
// sends a real TCP RST (with valid sequence numbers) to the kernel,
// which surfaces as ECONNREFUSED on the application's read().
//
// Why Abort() rather than crafting RST/ICMP packets by hand and
// writing them to the TUN fd?
//   - Abort() draws the seq number from the endpoint's own sndNxt /
//     sndWnd state. A hand-crafted RST with seq=0 is rejected by the
//     kernel's tcp_validate_incoming (RFC 5961) because it's outside
//     the receiver's window.
//   - Writing raw packets to the TUN fd on Linux requires
//     fdbased.NewInjectable instead of the regular New — the gvisor
//     endpoint doesn't expose io.Writer, and the regular WritePackets
//     path was reported to be state-checked. Switching the fork's
//     tun_netstack.go is invasive.
//   - The TCP RST kernel socket sees is the same one gvisor would
//     emit on a normal connection close — there's nothing custom
//     about it that could trip the kernel.
//
// Limitation: gvisor's Abort() always emits RST, regardless of the
// underlying failure. That means every smart-error path surfaces as
// ECONNREFUSED to the application — even host-unreachable, which would
// more correctly be EHOSTUNREACH. This is a known trade-off. If we
// ever need finer-grained errnos, we'd have to inject ICMP Destination
// Unreachable into gvisor's stack via Stack.Inject (a different API
// path that this fork doesn't currently expose).
//
// Returns true when the endpoint was found and aborted (caller should
// skip the deferred originConn.Close()). Returns false when no stack
// is wired up, the endpoint can't be found (already closed), or the
// classification didn't match a known category — caller falls back
// to graceful close.
func (t *Tunnel) injectSmartError(m *M.Metadata, id stack.TransportEndpointID, dialErr error) bool {
	// classifyForSmartError is a coarse boolean at this point — we
	// use it only to suppress smart-error on unrecognized categories
	// (which currently means: nothing matches → graceful close). The
	// actual RST is always a RST regardless of category, because
	// Abort() doesn't take a category argument.
	category := classifyForSmartError(dialErr)
	if category == "" {
		// No recognized category — fall back to graceful close.
		return false
	}

	stk := t.getStack()
	if stk == nil {
		log.Debugf("[TCP] smart-error: no gvisor stack wired up; falling back to graceful close")
		return false
	}

	// Look up the gvisor endpoint. The ID passed in here is the same
	// TransportEndpointID that the kernel-side socket was created
	// from — same local IP/port (target's IP/22), same remote IP/port
	// (app's IP/ephemeral). NICID=0 is the wildcard "any NIC" sentinel
	// (findTransportEndpoint falls back to 0 if the requested NICID
	// isn't in the table).
	ep := stk.FindTransportEndpoint(
		header.IPv4ProtocolNumber,
		header.TCPProtocolNumber,
		id,
		0,
	)
	if ep == nil {
		log.Warnf("[TCP] smart-error: endpoint for %s not found (already closed?)",
			m.DestinationAddress())
		return false
	}

	log.Infof("[TCP] smart-error: aborting endpoint for %s (category=%s)",
		m.DestinationAddress(), category)
	ep.Abort()
	return true
}

// classifyForSmartError maps a dial error to a category used by
// injectSmartError. Mirrors the classification logic in the
// classifyingProxy wrapper but kept in the library so the error
// response doesn't depend on the application.
//
// Currently only the boolean "is this an error we want smart-error
// for?" matters — see injectSmartError comment.
func classifyForSmartError(err error) string {
	if err == nil {
		return ""
	}
	// Deadline sentinels first.
	if errors.Is(err, socks5.ErrDialTimeout) || errors.Is(err, httpproxy.ErrDialTimeout) {
		return "proxy-timeout"
	}
	if errors.Is(err, socks5.ErrDialUnreachable) || errors.Is(err, httpproxy.ErrDialUnreachable) {
		return "proxy-gave-up"
	}
	var s5err *socks5.ReplyError
	if errors.As(err, &s5err) {
		switch s5err.Reply {
		case 0x03:
			return "network-unreachable"
		case 0x04:
			return "host-unreachable"
		case 0x05:
			return "connection-refused"
		}
	}
	var herr *httpproxy.StatusError
	if errors.As(err, &herr) {
		switch herr.Code {
		case 502, 503, 504:
			return "connection-refused" // proxy reached upstream but it failed
		}
	}
	return ""
}

// pipe copies data to & from provided net.Conn(s) bidirectionally.
func pipe(origin, remote net.Conn) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	go unidirectionalStream(remote, origin, "origin->remote", &wg)
	go unidirectionalStream(origin, remote, "remote->origin", &wg)

	wg.Wait()
}

func unidirectionalStream(dst, src net.Conn, dir string, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := buffer.Get(buffer.RelayBufferSize)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil {
		log.Debugf("[TCP] copy data for %s: %v", dir, err)
	}
	buffer.Put(buf)
	// Do the upload/download side TCP half-close.
	if cr, ok := src.(interface{ CloseRead() error }); ok {
		cr.CloseRead()
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	// Set TCP half-close timeout.
	dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
}
