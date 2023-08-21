package option

import (
	"net/netip"

	"github.com/sagernet/sing-box/common/json"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

type ProxyProviderOptions struct {
	Tag                  string                                    `json:"tag"`
	URL                  string                                    `json:"url"`
	CacheFile            string                                    `json:"cache_file,omitempty"`
	ForceUpdate          Duration                                  `json:"force_update,omitempty"`
	HTTP3                bool                                      `json:"http3,omitempty"`
	RequestTimeout       Duration                                  `json:"request_timeout,omitempty"`
	RequestIP            *netip.Addr                               `json:"ip,omitempty"`
	DNS                  string                                    `json:"dns,omitempty"`
	TagFormat            string                                    `json:"tag_format,omitempty"`
	Filter               *ProxyProviderFilterOptions               `json:"filter,omitempty"`
	DefaultOutbound      string                                    `json:"default_outbound,omitempty"`
	RequestDialerOptions *ProxyProviderRequestDialerOptions        `json:"request_dialer,omitempty"`
	DialerOptions        *DialerOptions                            `json:"dialer,omitempty"`
	CustomGroup          Listable[ProxyProviderCustomGroupOptions] `json:"custom_group,omitempty"`
}

type ProxyProviderCustomGroupOptions struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
	ProxyProviderFilterOptions
	SelectorOptions SelectorOutboundOptions `json:"-"`
	URLTestOptions  URLTestOutboundOptions  `json:"-"`
}

type _proxyProviderCustomGroupOptions ProxyProviderCustomGroupOptions

func (p *ProxyProviderCustomGroupOptions) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, (*_proxyProviderCustomGroupOptions)(p))
	if err != nil {
		return err
	}
	var h any
	switch p.Type {
	case C.TypeSelector:
		h = &p.SelectorOptions
	case C.TypeURLTest:
		h = &p.URLTestOptions
	default:
		return E.New("unknown group type: ", p.Type)
	}
	err = UnmarshallExcluded(data, (*_proxyProviderCustomGroupOptions)(p), h)
	if err != nil {
		return E.Cause(err, "proxyprovider options")
	}
	return nil
}

func (p ProxyProviderCustomGroupOptions) MarshalJSON() ([]byte, error) {
	var v any
	switch p.Type {
	case C.TypeSelector:
		v = p.SelectorOptions
	case C.TypeURLTest:
		v = p.URLTestOptions
	default:
		return nil, E.New("unknown group type: ", p.Type)
	}
	return MarshallObjects((*_proxyProviderCustomGroupOptions)(&p), v)
}

type ProxyProviderFilterOptions struct {
	Rule      Listable[*Filter] `json:"rule"`
	WhiteMode bool              `json:"white_mode,omitempty"`
}

type ProxyProviderRequestDialerOptions struct {
	BindInterface      string         `json:"bind_interface,omitempty"`
	Inet4BindAddress   *ListenAddress `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress   *ListenAddress `json:"inet6_bind_address,omitempty"`
	ProtectPath        string         `json:"protect_path,omitempty"`
	RoutingMark        int            `json:"routing_mark,omitempty"`
	ReuseAddr          bool           `json:"reuse_addr,omitempty"`
	ConnectTimeout     Duration       `json:"connect_timeout,omitempty"`
	TCPFastOpen        bool           `json:"tcp_fast_open,omitempty"`
	TCPMultiPath       bool           `json:"tcp_multi_path,omitempty"`
	UDPFragment        *bool          `json:"udp_fragment,omitempty"`
	UDPFragmentDefault bool           `json:"-"`
}
