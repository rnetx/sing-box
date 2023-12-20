package option

import "github.com/sagernet/sing/common/json"

type ProviderOutboundOptions struct {
	DialerOptions
	SelectorOptions SelectorOutboundOptions         `json:"outbound"`
	URL             string                          `json:"url"`
	CacheTag        string                          `json:"cache_tag"`
	UpdateInterval  Duration                        `json:"update_interval"`
	RequestTimeout  Duration                        `json:"request_timeout"`
	HTTP3           bool                            `json:"http3"`
	UserAgent       string                          `json:"user_agent"`
	HotReload       bool                            `json:"hot_reload"`
	Actions         []ProviderOutboundActionOptions `json:"actions"`
}

type ProviderOutboundActionOptions struct {
	Type       string         `json:"type"`
	RawMessage map[string]any `json:"-"`
}

type _ProviderOutboundActionOptions ProviderOutboundActionOptions

func (p *ProviderOutboundActionOptions) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*_ProviderOutboundActionOptions)(p))
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, &p.RawMessage)
	if err != nil {
		return err
	}
	if p.RawMessage != nil {
		delete(p.RawMessage, "type")
	}
	return nil
}
