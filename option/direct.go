package option

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type DirectInboundOptions struct {
	ListenOptions
	Network         NetworkList `json:"network,omitempty"`
	OverrideAddress string      `json:"override_address,omitempty"`
	OverridePort    uint16      `json:"override_port,omitempty"`
}

type DirectOutboundOptions struct {
	DialerOptions
	OverrideAddress string                                  `json:"override_address,omitempty"`
	OverridePort    uint16                                  `json:"override_port,omitempty"`
	Override        Listable[DirectOutboundOverrideOptions] `json:"override,omitempty"`
	ProxyProtocol   uint8                                   `json:"proxy_protocol,omitempty"`
}

type _DirectOutboundOverrideOptions struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type DirectOutboundOverrideOptions struct {
	Address netip.Prefix `json:"address"`
	Port    uint16       `json:"port"`
}

func (o *DirectOutboundOverrideOptions) UnmarshalJSON(content []byte) error {
	var _options _DirectOutboundOverrideOptions
	err := json.Unmarshal(content, &_options)
	if err != nil {
		return err
	}
	o.Port = _options.Port
	if _options.Address != "" {
		ip, err1 := netip.ParseAddr(_options.Address)
		if err1 == nil {
			var bits int
			if ip.Is4() {
				bits = 32
			} else {
				bits = 128
			}
			o.Address = netip.PrefixFrom(ip, bits)
			return nil
		}
		prefix, err2 := netip.ParsePrefix(_options.Address)
		if err2 == nil {
			o.Address = prefix
			return nil
		}
		return E.New("invalid address: ", _options.Address, ": ", err1, " | ", err2)
	}
	return nil
}
