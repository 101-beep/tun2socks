package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/101-beep/tun2socks/v2/dialer"
	M "github.com/101-beep/tun2socks/v2/metadata"
	"github.com/101-beep/tun2socks/v2/proxy"
	"github.com/101-beep/tun2socks/v2/proxy/internal/utils"
)

var _ proxy.Proxy = (*HTTP)(nil)

type HTTP struct {
	addr string
	user string
	pass string
}

func New(addr, user, pass string) (*HTTP, error) {
	return &HTTP{
		addr: addr,
		user: user,
		pass: pass,
	}, nil
}

// DefaultDialTimeout is the maximum time to wait for an HTTP CONNECT
// response. If zero (default), no deadline is applied and the dial may
// block indefinitely until the proxy's own timeout kicks in.
//
// Setting this lets the caller distinguish:
//
//   - "host unreachable / filtered" (we time out before the proxy replies)
//   - "port refused" (proxy replies 4xx/5xx quickly)
//   - "proxy closed silently" (EOF within the deadline)
//
// Set this from your application's main() before any dial happens:
//
//	http.DefaultDialTimeout = 3 * time.Second
var DefaultDialTimeout time.Duration

// ErrDialTimeout is returned by HTTP.shakeHand when the HTTP proxy
// did not send a CONNECT response within DefaultDialTimeout.
//
// Use errors.Is to detect:
//
//	if errors.Is(err, http.ErrDialTimeout) { /* unreachable / filtered */ }
var ErrDialTimeout = errors.New("http: dial timeout (no reply from proxy)")

// ErrDialUnreachable is returned when the HTTP proxy closed the
// underlying connection without sending a CONNECT response. Same
// semantics as socks5.ErrDialUnreachable — the proxy is non-RFC and
// just shut the TCP connection instead of sending a status code.
var ErrDialUnreachable = errors.New("http: dial unreachable (proxy closed connection without reply)")

func (h *HTTP) DialContext(ctx context.Context, metadata *M.Metadata) (c net.Conn, err error) {
	c, err = dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", h.addr, err)
	}
	utils.SetKeepAlive(c)

	defer func(c net.Conn) {
		utils.SafeConnClose(c, err)
	}(c)

	err = h.shakeHand(metadata, c)
	return c, err
}

func (h *HTTP) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}

func (h *HTTP) shakeHand(metadata *M.Metadata, rw io.ReadWriter) error {
	addr := metadata.DestinationAddress()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: addr,
		},
		Host: addr,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}

	if h.user != "" && h.pass != "" {
		req.Header.Set("Proxy-Authorization", fmt.Sprintf("Basic %s", basicAuth(h.user, h.pass)))
	}

	if err := req.Write(rw); err != nil {
		return err
	}

	// Apply a read deadline so we can distinguish "no reply" cases.
	// rw is always a net.Conn here (came from dialer.DialContext) but
	// assert to be safe — if it's not, we just skip the deadline.
	if DefaultDialTimeout > 0 {
		if conn, ok := rw.(net.Conn); ok {
			_ = conn.SetReadDeadline(time.Now().Add(DefaultDialTimeout))
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		// Classify the failure so the caller can switch on it.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return ErrDialTimeout
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: %v", ErrDialUnreachable, err)
		}
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return &StatusError{Code: resp.StatusCode, Status: resp.Status}
	}
}

// The Basic authentication scheme is based on the model that the client
// needs to authenticate itself with a user-id and a password for each
// protection space ("realm"). The realm value is a free-form string
// that can only be compared for equality with other realms on that
// server. The server will service the request only if it can validate
// the user-id and password for the protection space applying to the
// requested resource.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func Parse(u *url.URL) (proxy.Proxy, error) {
	address, username := u.Host, u.User.Username()
	password, _ := u.User.Password()
	return New(address, username, password)
}

func init() {
	proxy.RegisterProtocol("http", Parse)
}

// StatusError carries the HTTP status code from a failed CONNECT so callers
// can switch on it via errors.As.
type StatusError struct {
	Code   int
	Status string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("HTTP connect status: %s", e.Status)
}
