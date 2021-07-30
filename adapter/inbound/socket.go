package inbound

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks4"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target interface{}, conn net.Conn, source C.Type) *context.ConnContext {
	var metadata *C.Metadata
	if addr, ok := target.(socks5.Addr); ok {
		metadata = parseSocks5Addr(addr)
	} else {
		metadata = parseSocks4Addr(target.(*socks4.Addr))
	}

	metadata.NetWork = C.TCP
	metadata.Type = source
	if ip, port, err := parseAddr(conn.RemoteAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}

	return context.NewConnContext(conn, metadata)
}
