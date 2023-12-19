package provider

import (
	"encoding/json"
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type tagFormatAction struct {
	outboundMatcher *OutboundMatcher
	tagFormat       string
	formatGroup     bool
}

type tagFormatActionOptions struct {
	Rules       []string `json:"rules"`
	TagFormat   string   `json:"tag_format"`
	FormatGroup bool     `json:"format_group"`
}

func init() {
	RegisterAction("tag_format", func() Action {
		return &tagFormatAction{}
	})
}

func (a *tagFormatAction) Unmarshal(m map[string]any) error {
	raw, _ := json.Marshal(m)
	var options tagFormatActionOptions
	err := json.Unmarshal(raw, &options)
	if err != nil {
		return err
	}
	outboundMatcher, err := NewOutboundMatcher(options.Rules)
	if err != nil {
		return err
	}
	a.outboundMatcher = outboundMatcher
	if options.TagFormat == "" {
		return E.New("tag_format is required")
	}
	a.formatGroup = options.FormatGroup
	return nil
}

func (a *tagFormatAction) Apply(p *PreProcessSet) error {
	p.ForeachOutbound(func(options *option.Outbound) bool {
		if a.outboundMatcher.Match(options) {
			options.Tag = fmt.Sprintf(a.tagFormat, options.Tag)
			switch options.Type {
			case C.TypeSelector:
				for i, outbound := range options.SelectorOptions.Outbounds {
					options.SelectorOptions.Outbounds[i] = fmt.Sprintf(a.tagFormat, outbound)
				}
				if options.SelectorOptions.Default != "" {
					options.SelectorOptions.Default = fmt.Sprintf(a.tagFormat, options.SelectorOptions.Default)
				}
			case C.TypeURLTest:
				for i, outbound := range options.URLTestOptions.Outbounds {
					options.URLTestOptions.Outbounds[i] = fmt.Sprintf(a.tagFormat, outbound)
				}
			}
		}
		return true
	})
	if a.formatGroup {
		p.ForeachExternalOutbound(func(options *option.Outbound) bool {
			if a.outboundMatcher.Match(options) {
				options.Tag = fmt.Sprintf(a.tagFormat, options.Tag)
				switch options.Type {
				case C.TypeSelector:
					for i, outbound := range options.SelectorOptions.Outbounds {
						options.SelectorOptions.Outbounds[i] = fmt.Sprintf(a.tagFormat, outbound)
					}
					if options.SelectorOptions.Default != "" {
						options.SelectorOptions.Default = fmt.Sprintf(a.tagFormat, options.SelectorOptions.Default)
					}
				case C.TypeURLTest:
					for i, outbound := range options.URLTestOptions.Outbounds {
						options.URLTestOptions.Outbounds[i] = fmt.Sprintf(a.tagFormat, outbound)
					}
				}
			}
			return true
		})
	}
	return nil
}
