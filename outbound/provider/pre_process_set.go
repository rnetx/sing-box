package provider

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type PreProcessSet struct {
	actions                     []Action
	outboundOptions             []option.Outbound
	outboundOptionByTag         map[string]*option.Outbound
	externalOutboundOptions     []option.Outbound
	externalOutboundOptionByTag map[string]*option.Outbound
}

func NewPreProcessSet(options []option.Outbound, actions []Action) *PreProcessSet {
	p := &PreProcessSet{
		actions:             actions,
		outboundOptions:     options,
		outboundOptionByTag: make(map[string]*option.Outbound, len(options)),
	}
	for i := range p.outboundOptions {
		p.outboundOptionByTag[p.outboundOptions[i].Tag] = &p.outboundOptions[i]
	}
	return p
}

func (p *PreProcessSet) initExternalOutboundOptions() {
	if p.externalOutboundOptions == nil {
		p.externalOutboundOptions = make([]option.Outbound, 0)
		p.externalOutboundOptionByTag = make(map[string]*option.Outbound)
	}
}

func (p *PreProcessSet) ForeachOutbound(f func(options *option.Outbound) bool) bool {
	for i := range p.outboundOptions {
		if !f(&p.outboundOptions[i]) {
			return false
		}
	}
	return true
}

func (p *PreProcessSet) GetOutbound(tag string) (*option.Outbound, bool) {
	outbound, ok := p.outboundOptionByTag[tag]
	return outbound, ok
}

func (p *PreProcessSet) DeleteOutbound(tag string) {
	delete(p.outboundOptionByTag, tag)
	for i := range p.outboundOptions {
		if p.outboundOptions[i].Tag == tag {
			p.outboundOptions = append(p.outboundOptions[:i], p.outboundOptions[i+1:]...)
			break
		}
	}
}

func (p *PreProcessSet) ForeachExternalOutbound(f func(options *option.Outbound) bool) bool {
	for i := range p.externalOutboundOptions {
		if !f(&p.externalOutboundOptions[i]) {
			return false
		}
	}
	return true
}

func (p *PreProcessSet) GetExternalOutbound(tag string) (*option.Outbound, bool) {
	if p.externalOutboundOptionByTag != nil {
		outbound, ok := p.externalOutboundOptionByTag[tag]
		return outbound, ok
	}
	return nil, false
}

func (p *PreProcessSet) DeleteExternalOutbound(tag string) {
	if p.externalOutboundOptionByTag != nil {
		delete(p.externalOutboundOptionByTag, tag)
		for i := range p.externalOutboundOptions {
			if p.externalOutboundOptions[i].Tag == tag {
				p.externalOutboundOptions = append(p.externalOutboundOptions[:i], p.externalOutboundOptions[i+1:]...)
				break
			}
		}
	}
}

func (p *PreProcessSet) AddExternalOutbound(options *option.Outbound) {
	p.initExternalOutboundOptions()
	p.externalOutboundOptions = append(p.externalOutboundOptions, *options)
	p.externalOutboundOptionByTag[options.Tag] = options
}

func (p *PreProcessSet) Build() (outboundOptions []option.Outbound, err error) {
	for i, action := range p.actions {
		err = action.Apply(p)
		if err != nil {
			return nil, E.Cause(err, "run action[", i, "] failed")
		}
	}
	outboundOptions = make([]option.Outbound, 0, len(p.outboundOptions)+len(p.externalOutboundOptions))
	outboundOptions = append(outboundOptions, p.outboundOptions...)
	outboundOptions = append(outboundOptions, p.externalOutboundOptions...)
	return
}
