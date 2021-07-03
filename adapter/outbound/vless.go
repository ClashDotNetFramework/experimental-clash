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
	"net/url"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/transport/vless"
	"github.com/Dreamacro/clash/transport/vmess"
	C "github.com/Dreamacro/clash/constant"
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
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UUID           string            `proxy:"uuid"`
	UDP            bool              `proxy:"udp,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	Network        string            `proxy:"network,omitempty"`
	WSPath         string            `proxy:"ws-path,omitempty"`
	WSHeaders      map[string]string `proxy:"ws-headers,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	ServerName     string            `proxy:"servername,omitempty"`
	Flow           string            `proxy:"flow,omitempty"`
}

func (v *Vless) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	switch v.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vmess.WebsocketConfig{
			Host: host,
			Port: port,
			Path: v.option.WSPath,
		}

		var ed uint32
		if u, err := url.Parse(v.option.WSPath); err == nil {
			if q := u.Query(); q.Get("ed") != "" {
				Ed, _ := strconv.Atoi(q.Get("ed"))
				ed = uint32(Ed)
				q.Del("ed")
				u.RawQuery = q.Encode()
				wsOpts.Path = u.String()
			}
		}
		wsOpts.Ed = ed

		if len(v.option.WSHeaders) != 0 {
			header := http.Header{}
			for key, value := range v.option.WSHeaders {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		if v.option.TLS {
			wsOpts.TLS = true
			wsOpts.SkipCertVerify = v.option.SkipCertVerify
			wsOpts.ServerName = v.option.ServerName
		}
		if wsOpts.Ed > 0 {
			c, err = vmess.StreamWebsocketEDConn(c, wsOpts)
		} else {
			c, err = vmess.StreamWebsocketConn(c, wsOpts, nil)
		}
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

func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := dialer.DialContext(ctx, "tcp", v.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)

	c, err = v.StreamConn(c, metadata)
	return NewConn(c, v), err
}

func (v *Vless) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	c, err := dialer.DialContext(ctx, "tcp", v.addr)
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
			name: option.Name,
			addr: net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:   C.Vless,
			udp:  true,
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
