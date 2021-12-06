package tunnel

import C "github.com/Dreamacro/clash/constant"

func safeAssertProxyType(adapter C.Proxy, metadata *C.Metadata, proxyType C.AdapterType) bool {
	if adapter == nil || metadata == nil {
		return false
	}
	proxy := adapter.Unwrap(metadata)
	if proxy == nil {
		return false
	}

	if proxy.Type() == proxyType {
		return true
	} else {
		return false
	}
}
