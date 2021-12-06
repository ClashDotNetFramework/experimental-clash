package obfs

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/Dreamacro/clash/transport/vmess"
)

// Option is options of websocket obfs
type Option struct {
	Host           string
	Port           string
	Path           string
	Headers        map[string]string
	TLS            bool
	SkipCertVerify bool
	Mux            bool
}

// NewV2rayObfs return a HTTPObfs
func NewV2rayObfs(conn net.Conn, option *Option) (net.Conn, error) {
	header := http.Header{}
	for k, v := range option.Headers {
		header.Add(k, v)
	}

	config := &vmess.WebsocketConfig{
		Host:    option.Host,
		Port:    option.Port,
		Path:    option.Path,
		Headers: header,
	}

	if option.TLS {
		config.TLS = true
		config.TLSConfig = &tls.Config{
			ServerName:         option.Host,
			InsecureSkipVerify: option.SkipCertVerify,
			NextProtos:         []string{"http/1.1"},
		}
		if host := config.Headers.Get("Host"); host != "" {
			config.TLSConfig.ServerName = host
		}
	}

	var err error
	conn, err = vmess.StreamWebsocketConn(conn, config)
	if err != nil {
		return nil, err
	}

	if option.Mux {
		conn = NewMux(conn, MuxOption{
			ID:   [2]byte{0, 0},
			Host: "127.0.0.1",
			Port: 0,
		})
	}
	return conn, nil
}
