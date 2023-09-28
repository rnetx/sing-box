package option

import (
	"net/netip"

	"github.com/sagernet/sing-box/common/json"
	E "github.com/sagernet/sing/common/exceptions"
)

type RandomAddrOutboundOptions struct {
	Addresses Listable[RandomAddress] `json:"addresses,omitempty"`
	UDP       bool                    `json:"udp,omitempty"`
	DialerOptions
}

type RandomAddress struct {
	IP   *IPPrefix `json:"ip,omitempty"`
	Port *uint16   `json:"port,omitempty"`
}

type _RandomAddress RandomAddress

func (r *RandomAddress) UnmarshalJSON(data []byte) error {
	var _r _RandomAddress
	err := json.Unmarshal(data, &_r)
	if err != nil {
		return err
	}

	if _r.IP == nil && _r.Port == nil {
		return E.New("invalid address")
	}

	*r = RandomAddress(_r)
	return nil
}

type IPPrefix netip.Prefix

func (p *IPPrefix) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(s)
	if err == nil {
		*p = IPPrefix(prefix)
		return nil
	}

	ip, err := netip.ParseAddr(s)
	if err != nil {
		return E.New("invalid address: %s", s)
	}

	var bit int
	if ip.Is6() {
		bit = 128
	} else {
		bit = 32
	}
	*p = IPPrefix(netip.PrefixFrom(ip, bit))

	return nil
}

func (p IPPrefix) MarshalJSON() ([]byte, error) {
	prefix := netip.Prefix(p)
	if prefix.Bits() == 32 || prefix.Bits() == 128 {
		return json.Marshal(prefix.Addr().String())
	}
	return json.Marshal(prefix.String())
}
