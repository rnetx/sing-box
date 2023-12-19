package provider

import (
	"encoding/json"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type groupAction struct {
	groupOutboundOptions option.Outbound
	outboundMatcher      *OutboundMatcher
}

type groupActionOptions struct {
	Rules    []string        `json:"rules"`
	Outbound option.Outbound `json:"outbound"`
}

func init() {
	RegisterAction("group", func() Action {
		return &groupAction{}
	})
}

func (a *groupAction) Unmarshal(m map[string]any) error {
	raw, _ := json.Marshal(m)
	var options groupActionOptions
	err := json.Unmarshal(raw, &options)
	if err != nil {
		return err
	}
	outboundMatcher, err := NewOutboundMatcher(options.Rules)
	if err != nil {
		return err
	}
	a.outboundMatcher = outboundMatcher
	switch options.Outbound.Type {
	case C.TypeSelector:
	case C.TypeURLTest:
	default:
		return E.New("invalid outbound type: ", options.Outbound.Type)
	}
	a.groupOutboundOptions = options.Outbound
	return nil
}

func (a *groupAction) Apply(p *PreProcessSet) error {
	outboundTags := make([]string, 0)
	p.ForeachOutbound(func(options *option.Outbound) bool {
		if a.outboundMatcher.Match(options) {
			outboundTags = append(outboundTags, options.Tag)
		}
		return true
	})
	groupOutboundOptions := a.groupOutboundOptions
	switch groupOutboundOptions.Type {
	case C.TypeSelector:
		groupOutboundOptions.SelectorOptions.Outbounds = outboundTags
	case C.TypeURLTest:
		groupOutboundOptions.URLTestOptions.Outbounds = outboundTags
	}
	p.AddExternalOutbound(&groupOutboundOptions)
	return nil
}
