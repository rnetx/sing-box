//go:build with_proxyprovider

package proxyprovider

import (
	"context"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

func NewProxyProvider(ctx context.Context, router adapter.Router, logFactory log.Factory, options option.ProxyProviderOptions) (*ProxyProvider, error) {
	if options.Tag == "" {
		return nil, E.New("missing proxyprovider tag")
	}
	if options.URL == "" {
		return nil, E.New("missing proxyprovider url")
	}

	p := &ProxyProvider{
		tag:        options.Tag,
		ctx:        ctx,
		router:     router,
		logFactory: logFactory,
		options:    options,
	}
	if logFactory != nil {
		p.logger = logFactory.NewLogger(F.ToString("proxyprovider", "[", options.Tag, "]"))
	}

	p.initRequestDialer()
	err := p.initDNS()
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *ProxyProvider) Tag() string {
	return p.tag
}

func (p *ProxyProvider) GetOutboundOptions() ([]option.Outbound, error) {
	if p.peerList == nil {
		return nil, E.New("proxy list is empty")
	}

	outbounds := make([]option.Outbound, 0)
	for i, px := range p.peerList {
		outboundOptions, err := px.GenerateOptions()
		if err != nil {
			continue
		}
		tag := px.Tag()
		if tag == "" {
			tag = F.ToString(p.Tag(), "-", i)
		}
		outboundOptions.Tag = tag
		outbounds = append(outbounds, *outboundOptions)
	}
	if len(outbounds) == 0 {
		return nil, E.New("proxy list is empty")
	}

	groupOutbounds, err := p.getCustomGroupOptions(&outbounds)
	if err != nil {
		return nil, E.Cause(err, "parse proxyprovider[", p.Tag(), "] custom group")
	}
	if groupOutbounds != nil {
		outbounds = append(outbounds, groupOutbounds...)
	}
	var globalDefaultOutbound string
	if p.options.DefaultOutbound != "" {
		for _, t := range outbounds {
			if t.Tag == p.options.DefaultOutbound {
				globalDefaultOutbound = t.Tag
				break
			}
		}
	}
	if p.options.TagFormat != "" {
		for i := range outbounds {
			switch outbounds[i].Type {
			case C.TypeSelector:
				for j := range outbounds[i].SelectorOptions.Outbounds {
					outbounds[i].SelectorOptions.Outbounds[j] = fmt.Sprintf(p.options.TagFormat, outbounds[i].SelectorOptions.Outbounds[j])
				}
				if outbounds[i].SelectorOptions.Default != "" {
					outbounds[i].SelectorOptions.Default = fmt.Sprintf(p.options.TagFormat, outbounds[i].SelectorOptions.Default)
				}
			case C.TypeURLTest:
				for j := range outbounds[i].URLTestOptions.Outbounds {
					outbounds[i].URLTestOptions.Outbounds[j] = fmt.Sprintf(p.options.TagFormat, outbounds[i].URLTestOptions.Outbounds[j])
				}
			default:
				outbounds[i].Tag = fmt.Sprintf(p.options.TagFormat, outbounds[i].Tag)
			}
		}
		if globalDefaultOutbound != "" {
			globalDefaultOutbound = fmt.Sprintf(p.options.TagFormat, globalDefaultOutbound)
		}
	}

	globalGroupTags := make([]string, 0)
	for _, out := range outbounds {
		globalGroupTags = append(globalGroupTags, out.Tag)
	}

	globalOutboundOptions := option.Outbound{}
	globalOutboundOptions.Tag = p.Tag()
	globalOutboundOptions.Type = C.TypeSelector
	globalOutboundOptions.SelectorOptions = option.SelectorOutboundOptions{
		Outbounds: globalGroupTags,
		Default:   globalDefaultOutbound,
	}

	outbounds = append(outbounds, globalOutboundOptions)

	return outbounds, nil
}

func (p *ProxyProvider) GetOutbounds() ([]adapter.Outbound, error) {
	if p.peerList == nil {
		return nil, E.New("proxy list is empty")
	}

	outboundOptions, err := p.GetOutboundOptions()
	if err != nil {
		return nil, E.Cause(err, "generate proxyprovider[", p.Tag(), "] options")
	}
	outbounds := make([]adapter.Outbound, 0)
	for _, outOptions := range outboundOptions {
		out, err := outbound.New(p.ctx, p.router, p.logFactory.NewLogger(F.ToString("outbound/", outOptions.Type, "[", outOptions.Tag, "]")), outOptions.Tag, outOptions)
		if err != nil {
			return nil, E.Cause(err, "create proxyprovider[", p.Tag(), "] outbound[", outOptions.Tag, "]")
		}
		outbounds = append(outbounds, out)
	}

	return outbounds, nil
}

func (p *ProxyProvider) getCustomGroups(outbounds []adapter.Outbound) ([]adapter.Outbound, error) {
	if p.options.CustomGroup == nil || len(p.options.CustomGroup) == 0 {
		return nil, nil
	}

	group := make([]adapter.Outbound, 0)
	for i, g := range p.options.CustomGroup {
		if g.Tag == "" {
			g.Tag = F.ToString(p.Tag(), "-", i)
		}
		outs := make([]string, 0)
		for _, out := range outbounds {
			if CheckFilter(&g.ProxyProviderFilterOptions, out.Tag(), out.Type()) {
				outs = append(outs, out.Tag())
			}
		}
		if len(outs) == 0 {
			continue
		}
		groupOutOptions := option.Outbound{}
		switch g.Type {
		case C.TypeSelector:
			groupOutOptions.Tag = g.Tag
			groupOutOptions.Type = C.TypeSelector
			groupOutOptions.SelectorOptions = g.SelectorOptions
			groupOutOptions.SelectorOptions.Outbounds = outs
		case C.TypeURLTest:
			groupOutOptions.Tag = g.Tag
			groupOutOptions.Type = C.TypeURLTest
			groupOutOptions.URLTestOptions = g.URLTestOptions
			groupOutOptions.URLTestOptions.Outbounds = outs
		default:
			return nil, E.New("unknown group type: ", g.Type)
		}
		groupOut, err := outbound.New(p.ctx, p.router, p.logFactory.NewLogger(F.ToString("outbound/", groupOutOptions.Type, "[", groupOutOptions.Tag, "]")), groupOutOptions.Tag, groupOutOptions)
		if err != nil {
			return nil, err
		}
		group = append(group, groupOut)
	}

	if len(group) == 0 {
		return nil, nil
	}

	return group, nil
}

func (p *ProxyProvider) getCustomGroupOptions(outbounds *[]option.Outbound) ([]option.Outbound, error) {
	if p.options.CustomGroup == nil || len(p.options.CustomGroup) == 0 {
		return nil, nil
	}

	group := make([]option.Outbound, 0)
	for i, g := range p.options.CustomGroup {
		if g.Tag == "" {
			g.Tag = F.ToString(p.Tag(), "-", i)
		}
		outs := make([]string, 0)
		for _, out := range *outbounds {
			if CheckFilter(&g.ProxyProviderFilterOptions, out.Tag, out.Type) {
				outs = append(outs, out.Tag)
			}
		}
		if len(outs) == 0 {
			continue
		}
		groupOutOptions := option.Outbound{}
		switch g.Type {
		case C.TypeSelector:
			groupOutOptions.Tag = g.Tag
			groupOutOptions.Type = C.TypeSelector
			groupOutOptions.SelectorOptions = g.SelectorOptions
			if groupOutOptions.SelectorOptions.Outbounds == nil {
				groupOutOptions.SelectorOptions.Outbounds = outs
			} else {
				groupOutOptions.SelectorOptions.Outbounds = append(groupOutOptions.SelectorOptions.Outbounds, outs...)
			}
		case C.TypeURLTest:
			groupOutOptions.Tag = g.Tag
			groupOutOptions.Type = C.TypeURLTest
			groupOutOptions.URLTestOptions = g.URLTestOptions
			if groupOutOptions.URLTestOptions.Outbounds == nil {
				groupOutOptions.URLTestOptions.Outbounds = outs
			} else {
				groupOutOptions.URLTestOptions.Outbounds = append(groupOutOptions.URLTestOptions.Outbounds, outs...)
			}
		default:
			return nil, E.New("unknown group type: ", g.Type)
		}
		group = append(group, groupOutOptions)
	}

	if len(group) == 0 {
		return nil, nil
	}

	return group, nil
}

func (p *ProxyProvider) GetUpdateTime() time.Time {
	p.subscriptionRawDataLock.RLock()
	defer p.subscriptionRawDataLock.RUnlock()
	return p.subscriptionRawData.UpdateTime
}

func (p *ProxyProvider) GetSubscribeInfo() adapter.SubScribeInfo {
	p.subscriptionRawDataLock.RLock()
	defer p.subscriptionRawDataLock.RUnlock()
	return &p.subscriptionRawData.SubScribeInfo
}
