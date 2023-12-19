package provider

import (
	"encoding/json"

	"github.com/sagernet/sing-box/option"
)

type ignoreAction struct {
	outboundMatcher *OutboundMatcher
}

type ignoreActionOptions struct {
	Rules []string `json:"rules"`
}

func init() {
	RegisterAction("ignore", func() Action {
		return &ignoreAction{}
	})
}

func (a *ignoreAction) Unmarshal(m map[string]any) error {
	raw, _ := json.Marshal(m)
	var options ignoreActionOptions
	err := json.Unmarshal(raw, &options)
	if err != nil {
		return err
	}
	outboundMatcher, err := NewOutboundMatcher(options.Rules)
	if err != nil {
		return err
	}
	a.outboundMatcher = outboundMatcher
	return nil
}

func (a *ignoreAction) Apply(p *PreProcessSet) error {
	outboundTags := make([]string, 0)
	p.ForeachOutbound(func(options *option.Outbound) bool {
		if a.outboundMatcher.Match(options) {
			outboundTags = append(outboundTags, options.Tag)
		}
		return true
	})
	for _, outbound := range outboundTags {
		p.DeleteOutbound(outbound)
	}
	return nil
}
