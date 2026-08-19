package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"

	"github.com/101-beep/tun2socks/v2/buffer"
	"github.com/101-beep/tun2socks/v2/core/adapter"
	"github.com/101-beep/tun2socks/v2/log"
	M "github.com/101-beep/tun2socks/v2/metadata"
	httpproxy "github.com/101-beep/tun2socks/v2/proxy/http"
	"github.com/101-beep/tun2socks/v2/transport/socks5"
	"github.com/101-beep/tun2socks/v2/tunnel/statistic"
)

func (t *Tunnel) handleTCPConn(originConn adapter.TCPConn) {
	// responded tracks whether injectSmartError already wrote a
	// kernel-level response (TCP RST / ICMP). When true, we skip
	// the deferred originConn.Close() — otherwise gvisor's Close
	// would send a graceful FIN that races with our RST/ICMP and
	// leaves the application confused (e.g. nxc reports "Unknown
	// SSH Version" instead of "No route to host").
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
		// a bare FIN (which confuses apps), inject the right
		// kernel-level response based on what the proxy told us.
		//
		//	connection-refused     → TCP RST               (ECONNREFUSED)
		//	host-unreachable       → ICMP Host Unreachable (EHOSTUNREACH)
		//	network-unreachable    → ICMP Net Unreachable  (ENETUNREACH)
		//	proxy-timeout          → ICMP Host Unreachable (EHOSTUNREACH)
		//	proxy-gave-up (EOF)    → ICMP Host Unreachable (EHOSTUNREACH)
		if t.injectSmartError(metadata, err) {
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
// appropriate kernel-level response, so applications on the host see
// the right error code instead of a generic "connection closed".
//
// Returns true when a packet was actually injected (caller should
// skip the deferred originConn.Close() to avoid racing FIN/RST).
// Returns false when no TUN writer is set or the classification
// didn't match a known category (caller falls back to graceful close).
func (t *Tunnel) injectSmartError(m *M.Metadata, dialErr error) bool {
	tunW := t.getTUNWriter()
	if tunW == nil {
		// No TUN writer registered — fall back to the original
		// behavior (graceful close via the deferred originConn.Close()).
		return false
	}

	switch classifyForSmartError(dialErr) {
	case "connection-refused":
		// Port closed, host alive. Kernel sees RST → ECONNREFUSED.
		log.Debugf("[TCP] smart-error: TCP RST for %s (connection-refused)", m.DestinationAddress())
		return writeTCPRST(tunW, m)

	case "network-unreachable":
		// Routing issue. Kernel sees ICMP Net Unreachable → ENETUNREACH.
		log.Debugf("[TCP] smart-error: ICMP Net Unreachable for %s", m.DestinationAddress())
		return writeICMPUnreachable(tunW, m, 0)

	case "host-unreachable", "proxy-timeout", "proxy-gave-up":
		// Host down or filtered. Kernel sees ICMP → EHOSTUNREACH
		// so the application knows it's a routing issue, not a port issue.
		log.Debugf("[TCP] smart-error: ICMP Host Unreachable for %s (%s)",
			m.DestinationAddress(), classifyForSmartError(dialErr))
		return writeICMPUnreachable(tunW, m, 1)

	default:
		// Unknown classification — let the defer do its default
		// graceful close via originConn.Close().
		log.Debugf("[TCP] smart-error: no classification match for %v", dialErr)
		return false
	}
}

// classifyForSmartError maps a dial error to a category used by
// injectSmartError. Mirrors the classification logic in the
// classifyingProxy wrapper but kept in the library so the error
// response doesn't depend on the application.
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

// writeTCPRST writes a TCP RST packet to the TUN so the kernel returns
// ECONNREFUSED to the application.
//
//	IPv4: src=targetIP, dst=clientIP, proto=TCP
//	TCP:  srcPort=targetPort, dstPort=clientPort, flags=RST|ACK
//
// The src IP is the target (the IP the application was trying to reach)
// so the RST looks like it came from the server that closed the port.
func writeTCPRST(w io.Writer, m *M.Metadata) bool {
	if !m.SrcIP.Is4() || !m.DstIP.Is4() {
		return false
	}
	srcIP := m.SrcIP.AsSlice() // client IP
	dstIP := m.DstIP.AsSlice() // target IP
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return false
	}

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ipHdr[2:4], 40)
	ipHdr[6] = 0x40 // DF
	ipHdr[8] = 64   // TTL
	ipHdr[9] = 6    // TCP
	copy(ipHdr[12:16], dstIP) // src = target (the closed-port server)
	copy(ipHdr[16:20], srcIP) // dst = originating client

	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(m.DstPort)) // src = target port
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(m.SrcPort)) // dst = client port
	// seq=0, ack=0
	tcpHdr[12] = 0x50 // data offset = 5
	tcpHdr[13] = 0x14 // RST|ACK
	// window=0

	pkt := append(ipHdr, tcpHdr...)

	// IP header checksum.
	ipCS := checksum.Checksum(pkt[:20], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	// TCP checksum with pseudo-header.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], dstIP)
	copy(pseudo[4:8], srcIP)
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	tcpCS := checksum.Checksum(append(pseudo, tcpHdr...), 0)
	binary.BigEndian.PutUint16(pkt[20+16:20+18], tcpCS)

	return injectToTUN(w, pkt)
}

// writeICMPUnreachable writes an ICMPv4 Destination Unreachable packet
// to the TUN so the kernel returns EHOSTUNREACH (or ENETUNREACH) to
// the application.
//
// Packet layout (RFC 792):
//
//	IP header (20)         — src=tunIP, dst=clientIP, proto=ICMP(1)
//	ICMP header (8)        — type=3, code=0|1, cksum, unused=0
//	Quoted IP hdr (20)     — the original packet's IP header
//	Quoted payload (8)     — first 8 bytes of original L4 (enough for
//	                         the kernel to match it to the right socket)
//
//	code=0 → network unreachable
//	code=1 → host unreachable
func writeICMPUnreachable(w io.Writer, m *M.Metadata, code uint8) bool {
	if !m.SrcIP.Is4() || !m.DstIP.Is4() {
		return false
	}
	srcIP := m.SrcIP.AsSlice() // application IP (the original sender)
	dstIP := m.DstIP.AsSlice() // target IP (the unreachable host)
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return false
	}

	const (
		ipHdrLen     = 20
		icmpHdrLen   = 8
		quotedIPLen  = 20
		quotedPayLen = 8
		totalLen     = ipHdrLen + icmpHdrLen + quotedIPLen + quotedPayLen // 56
	)

	// Outer IP header: src=ourTunIP, dst=clientIP, proto=ICMP.
	ipHdr := make([]byte, ipHdrLen)
	ipHdr[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ipHdr[2:4], totalLen)
	ipHdr[6] = 0x40 // DF
	ipHdr[8] = 64   // TTL
	ipHdr[9] = 1    // ICMP
	// The "source" of the ICMP error is the IP that the application
	// was trying to reach. This matches what a real router would do
	// (it would source the ICMP from the destination's network).
	// Some kernels accept any source; using the target IP makes the
	// error look like it came from the host that the application
	// was trying to talk to.
	copy(ipHdr[12:16], dstIP)
	copy(ipHdr[16:20], srcIP)

	// ICMP header: type=3, code, cksum, unused=0.
	icmp := make([]byte, icmpHdrLen)
	icmp[0] = 3  // Destination Unreachable
	icmp[1] = code
	// Bytes 2-3 = checksum, filled below.
	// Bytes 4-7 = unused (zero).

	// Quoted original IP header (20 bytes) — minimal, the kernel only
	// uses src/dst to match the ICMP to a socket.
	quotedIP := make([]byte, quotedIPLen)
	quotedIP[0] = 0x45
	binary.BigEndian.PutUint16(quotedIP[2:4], quotedIPLen+quotedPayLen)
	quotedIP[6] = 0x40
	quotedIP[8] = 64
	quotedIP[9] = 6 // TCP (the original L4 was TCP)
	copy(quotedIP[12:16], dstIP) // original destination
	copy(quotedIP[16:20], srcIP) // original source

	// Quoted original L4 (8 bytes — TCP source+dst ports are here).
	quotedPay := make([]byte, quotedPayLen)
	binary.BigEndian.PutUint16(quotedPay[0:2], uint16(m.DstPort))
	binary.BigEndian.PutUint16(quotedPay[2:4], uint16(m.SrcPort))

	// Assemble: ipHdr + icmp + quotedIP + quotedPay
	icmpBody := append(icmp, quotedIP...)
	icmpBody = append(icmpBody, quotedPay...)
	pkt := append(ipHdr, icmpBody...)

	// IP header checksum.
	ipCS := checksum.Checksum(pkt[:ipHdrLen], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	// ICMP checksum (over ICMP header + body).
	icmpCS := checksum.Checksum(icmpBody, 0)
	binary.BigEndian.PutUint16(pkt[ipHdrLen+2:ipHdrLen+4], icmpCS)

	return injectToTUN(w, pkt)
}

// injectToTUN writes a raw IP packet directly to the TUN device so the
// kernel processes it as if it arrived from the network. Bypasses
// gvisor's LinkEndpoint.WritePackets (which rejects with "endpoint is
// in invalid state" from a non-stack goroutine) and goes straight to
// the TUN fd via io.Writer.
//
// Safe to call concurrently with gvisor's own writes — the TUN
// device's Write method is internally synchronized.
//
// Returns true on success, false on failure (the caller should fall
// back to the default graceful close in that case).
func injectToTUN(w io.Writer, packet []byte) bool {
	if w == nil {
		return false
	}
	n, err := w.Write(packet)
	if err != nil {
		log.Warnf("[TCP] smart-error: TUN write failed: %v", err)
		return false
	}
	if n != len(packet) {
		log.Warnf("[TCP] smart-error: TUN short write: %d/%d bytes", n, len(packet))
		return false
	}
	return true
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
