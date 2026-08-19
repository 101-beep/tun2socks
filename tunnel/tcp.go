package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	gbuffer "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
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
	defer originConn.Close()

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
		t.injectSmartError(metadata, err)
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
func (t *Tunnel) injectSmartError(m *M.Metadata, dialErr error) {
	linkEP := t.getLinkEndpoint()
	if linkEP == nil {
		// No link endpoint registered — fall back to the original
		// behavior (graceful close via the deferred originConn.Close()).
		return
	}

	switch classifyForSmartError(dialErr) {
	case "connection-refused":
		// Port closed, host alive. Kernel sees RST → ECONNREFUSED.
		writeTCPRST(linkEP, m)

	case "network-unreachable":
		// Routing issue. Kernel sees ICMP Net Unreachable → ENETUNREACH.
		writeICMPUnreachable(linkEP, m, 0)

	case "host-unreachable", "proxy-timeout", "proxy-gave-up":
		// Host down or filtered. Kernel sees ICMP → EHOSTUNREACH
		// so the application knows it's a routing issue, not a port issue.
		writeICMPUnreachable(linkEP, m, 1)

	default:
		// Unknown classification — do nothing extra, let Close() do
		// its default thing.
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
//	IPv4: src=tunIP, dst=srcIP, proto=TCP
//	TCP:  srcPort=dstPort, dstPort=srcPort, flags=RST|ACK
func writeTCPRST(linkEP stack.LinkEndpoint, m *M.Metadata) {
	if !m.SrcIP.Is4() || !m.DstIP.Is4() {
		return // IPv6 not handled here (most TUNs are v4)
	}
	srcIP := m.SrcIP.AsSlice()
	dstIP := m.DstIP.AsSlice()
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return
	}

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ipHdr[2:4], 40)
	ipHdr[6] = 0x40 // DF
	ipHdr[8] = 64   // TTL
	ipHdr[9] = 6    // TCP
	copy(ipHdr[12:16], dstIP) // src = our TUN IP
	copy(ipHdr[16:20], srcIP) // dst = originating client

	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(m.DstPort)) // src = original target port
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

	injectToTUN(linkEP, pkt)
}

// writeICMPUnreachable writes an ICMPv4 Destination Unreachable packet
// to the TUN so the kernel returns EHOSTUNREACH (or ENETUNREACH) to
// the application.
//
//	code=0 → network unreachable
//	code=1 → host unreachable
func writeICMPUnreachable(linkEP stack.LinkEndpoint, m *M.Metadata, code uint8) {
	if !m.SrcIP.Is4() || !m.DstIP.Is4() {
		return
	}
	srcIP := m.SrcIP.AsSlice()
	dstIP := m.DstIP.AsSlice()
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return
	}

	// IP header: src=tunIP, dst=srcIP, proto=ICMP
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], 20+8+28) // IP + ICMP + quoted IP
	ipHdr[6] = 0x40
	ipHdr[8] = 64
	ipHdr[9] = 1 // ICMP
	copy(ipHdr[12:16], dstIP)
	copy(ipHdr[16:20], srcIP)

	// ICMP header: type=3, code=code, cksum, unused=0
	icmp := make([]byte, 8)
	icmp[0] = 3 // Destination Unreachable
	icmp[1] = code
	// checksum and unused filled below

	// Quoted original IP header (we don't have the actual bytes, so
	// build a minimal header that identifies the target). The kernel
	// uses this for matching the response to a socket, not for
	// validity, so a stripped header is fine.
	quoted := make([]byte, 28)
	quoted[0] = 0x45
	binary.BigEndian.PutUint16(quoted[2:4], 40)
	quoted[6] = 0x40
	quoted[8] = 64
	quoted[9] = 6 // TCP (the original was TCP)
	copy(quoted[12:16], dstIP) // was the target
	copy(quoted[16:20], srcIP) // was the client
	binary.BigEndian.PutUint16(quoted[20:22], uint16(m.DstPort))
	binary.BigEndian.PutUint16(quoted[22:24], uint16(m.SrcPort))
	// 8 bytes of "original payload" — zero is fine for matching.

	icmp = append(icmp, quoted...)
	pkt := append(ipHdr, icmp...)

	// IP header checksum.
	ipCS := checksum.Checksum(pkt[:20], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	// ICMP checksum.
	icmpCS := checksum.Checksum(icmp, 0)
	binary.BigEndian.PutUint16(pkt[20+2:20+4], icmpCS)

	injectToTUN(linkEP, pkt)
}

// injectToTUN writes a raw IP packet to the TUN device via the
// LinkEndpoint, so the kernel processes it as if it arrived from the
// network. Safe to call concurrently with gvisor's own writes.
func injectToTUN(linkEP stack.LinkEndpoint, packet []byte) {
	if linkEP == nil {
		return
	}
	// The gvisor buffer API in this version has no NewVectorisedView;
	// build a View, copy the bytes in, wrap as a Buffer.
	view := gbuffer.NewViewSize(len(packet))
	view.Write(packet)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: gbuffer.MakeWithView(view),
	})
	defer pkt.DecRef()

	pkts := stack.PacketBufferList{}
	pkts.PushBack(pkt)

	if _, err := linkEP.WritePackets(pkts); err != nil {
		log.Debugf("[TCP] inject packet: %v", err)
	}
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
