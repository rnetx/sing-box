package option

import (
	"github.com/sagernet/sing-box/common/json"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

type ProxyProvider struct {
	Tag            string               `json:"tag"`
	Url            string               `json:"url"`
	UserAgent      string               `json:"download_ua,omitempty"`
	CacheFile      string               `json:"cache_file,omitempty"`
	UpdateInterval Duration             `json:"update_interval,omitempty"`
	RequestTimeout Duration             `json:"request_timeout,omitempty"`
	DNS            string               `json:"dns,omitempty"`
	TagFormat      string               `json:"tag_format,omitempty"`
	GlobalFilter   *ProxyProviderFilter `json:"global_filter,omitempty"`
	Groups         []ProxyProviderGroup `json:"groups,omitempty"`
	RequestDialer  DialerOptions        `json:"request_dialer,omitempty"`
	Dialer         *DialerOptions       `json:"dialer,omitempty"`
	RunningDetour  string               `json:"running_detour,omitempty"`
}

type ProxyProviderFilter struct {
	WhiteMode bool             `json:"white_mode,omitempty"`
	Rules     Listable[string] `json:"rules,omitempty"`
}

type _ProxyProviderGroup struct {
	Tag             string                  `json:"tag"`
	Type            string                  `json:"type"`
	SelectorOptions SelectorOutboundOptions `json:"-"`
	URLTestOptions  URLTestOutboundOptions  `json:"-"`
	Filter          *ProxyProviderFilter    `json:"filter,omitempty"`
}

type ProxyProviderGroup _ProxyProviderGroup

func (p ProxyProviderGroup) MarshalJSON() ([]byte, error) {
	var v any
	switch p.Type {
	case C.TypeSelector:
		v = p.SelectorOptions
	case C.TypeURLTest:
		v = p.URLTestOptions
	default:
		return nil, E.New("unknown outbound type: ", p.Type)
	}
	return MarshallObjects((_ProxyProviderGroup)(p), v)
}

func (p *ProxyProviderGroup) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_ProxyProviderGroup)(p))
	if err != nil {
		return err
	}
	var v any
	switch p.Type {
	case C.TypeSelector:
		v = &p.SelectorOptions
	case C.TypeURLTest:
		v = &p.URLTestOptions
	default:
		return E.New("unknown outbound type: ", p.Type)
	}
	err = UnmarshallExcluded(bytes, (*_ProxyProviderGroup)(p), v)
	if err != nil {
		return E.Cause(err, "proxyprovider group options")
	}
	return nil
}
