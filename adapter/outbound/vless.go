package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/vless"
	"github.com/Dreamacro/clash/transport/vmess"
	xtls "github.com/xtls/go"
)

const (
	// max packet length
	maxLength = 8192
)

var bufPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}

type Vless struct {
	*Base
	client *vless.Client
	option *VlessOption
}

type VlessOption struct {
	BasicOption
	Name           string    `proxy:"name"`
	Server         string    `proxy:"server"`
	Port           int       `proxy:"port"`
	UUID           string    `proxy:"uuid"`
	UDP            bool      `proxy:"udp,omitempty"`
	Network        string    `proxy:"network,omitempty"`
	Flow           string    `proxy:"flow,omitempty"`
	TLS            bool      `proxy:"tls,omitempty"`
	SkipCertVerify bool      `proxy:"skip-cert-verify,omitempty"`
	ServerName     string    `proxy:"servername,omitempty"`
	WSOpts         WSOptions `proxy:"ws-opts,omitempty"`

	// TODO: remove these until 2022
	WSHeaders map[string]string `proxy:"ws-headers,omitempty"`
	WSPath    string            `proxy:"ws-path,omitempty"`
}

func (v *Vless) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	switch v.option.Network {
	case "ws":
		if v.option.WSOpts.Path == "" {
			v.option.WSOpts.Path = v.option.WSPath
		}
		if len(v.option.WSOpts.Headers) == 0 {
			v.option.WSOpts.Headers = v.option.WSHeaders
		}

		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vmess.WebsocketConfig{
			Host:                host,
			Port:                port,
			Path:                v.option.WSOpts.Path,
			MaxEarlyData:        v.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName: v.option.WSOpts.EarlyDataHeaderName,
		}

		if len(v.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range v.option.WSHeaders {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		if v.option.TLS {
			wsOpts.TLS = true
			wsOpts.TLSConfig = &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			}
			if v.option.ServerName != "" {
				wsOpts.TLSConfig.ServerName = v.option.ServerName
			} else if host := wsOpts.Headers.Get("Host"); host != "" {
				wsOpts.TLSConfig.ServerName = host
			}
		}
		c, err = vmess.StreamWebsocketConn(c, wsOpts)
	default:
		// handle TLS
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)

			if v.option.Flow == vless.XRO || v.option.Flow == vless.XROU || v.option.Flow == vless.XRD || v.option.Flow == vless.XRDU {
				xtlsConfig := &xtls.Config{
					ServerName:         host,
					InsecureSkipVerify: v.option.SkipCertVerify,
				}

				if v.option.ServerName != "" {
					xtlsConfig.ServerName = v.option.ServerName
				}
				xtlsConn := xtls.Client(c, xtlsConfig)
				if err = xtlsConn.Handshake(); err != nil {
					return nil, err
				}

				c = xtlsConn
			} else {
				tlsConfig := &tls.Config{
					ServerName:         host,
					InsecureSkipVerify: v.option.SkipCertVerify,
				}
				if v.option.ServerName != "" {
					tlsConfig.ServerName = v.option.ServerName
				}
				tlsConn := tls.Client(c, tlsConfig)
				if err = tlsConn.Handshake(); err != nil {
					return nil, err
				}

				c = tlsConn
			}

		}
	}

	if err != nil {
		return nil, err
	}

	return v.client.StreamConn(c, parseVmessAddr(metadata))
}

func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)

	c, err = v.StreamConn(c, metadata)
	return NewConn(c, v), err
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vless) ListenPacketContextctx(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	if (v.option.Flow == vless.XRO || v.option.Flow == vless.XRD) && metadata.DstPort == "443" {
		return nil, fmt.Errorf("%s stopped UDP/443", v.option.Flow)
	}

	// vless use stream-oriented udp, so clash needs a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)
	c, err = v.StreamConn(c, metadata)
	if err != nil {
		return nil, fmt.Errorf("new vless client error: %v", err)
	}
	return newPacketConn(newVlessPacketConn(c, metadata.UDPAddr()), v), nil
}

func NewVless(option VlessOption) (*Vless, error) {
	var addons *vless.Addons
	if option.TLS && option.Network != "ws" && option.Flow != "" {
		switch option.Flow {
		case vless.XRO, vless.XRD, vless.XROU, vless.XRDU:
			addons = &vless.Addons{
				Flow: option.Flow,
			}
		default:
			return nil, fmt.Errorf("unsupported vless flow type: %s", option.Flow)
		}
	}

	client, err := vless.NewClient(option.UUID, addons)
	if err != nil {
		return nil, err
	}

	return &Vless{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Vmess,
			udp:   option.UDP,
			iface: option.Interface,
		},
		client: client,
		option: &option,
	}, nil
}

func newVlessPacketConn(c net.Conn, addr net.Addr) *vlessPacketConn {
	return &vlessPacketConn{Conn: c,
		rAddr: addr,
		cache: make([]byte, 0, maxLength+2),
	}
}

type vlessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	remain int
	mux    sync.Mutex
	cache  []byte
}

func (c *vlessPacketConn) writePacket(b []byte, addr net.Addr) (int, error) {
	length := len(b)
	defer func() {
		c.cache = c.cache[:0]
	}()
	c.cache = append(c.cache, byte(length>>8), byte(length))
	c.cache = append(c.cache, b...)
	n, err := c.Conn.Write(c.cache)
	if n > 2 {
		return n - 2, err
	}

	return 0, err
}

func (c *vlessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) <= maxLength {
		return c.writePacket(b, addr)
	}

	offset := 0
	total := len(b)
	for offset < total {
		cursor := offset + maxLength
		if cursor > total {
			cursor = total
		}

		n, err := c.writePacket(b[offset:cursor], addr)
		if err != nil {
			return offset + n, err
		}

		offset = cursor
	}

	return total, nil
}

func (c *vlessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	length := len(b)
	if c.remain > 0 {
		if c.remain < length {
			length = c.remain
		}

		n, err := c.Conn.Read(b[:length])
		if err != nil {
			return 0, nil, err
		}

		c.remain -= n
		return n, c.rAddr, nil
	}

	var packetLength uint16
	if err := binary.Read(c.Conn, binary.BigEndian, &packetLength); err != nil {
		return 0, nil, err
	}

	remain := int(packetLength)
	n, err := c.Conn.Read(b[:length])
	remain -= n
	if remain > 0 {
		c.remain = remain
	}
	return n, c.rAddr, err
}
