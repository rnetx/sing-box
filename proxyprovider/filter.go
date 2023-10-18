package proxyprovider

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/dlclark/regexp2"
)

type Filter struct {
	whiteMode bool
	rules     []FilterItem
}

func NewFilter(f *option.ProxyProviderFilter) (*Filter, error) {
	ff := &Filter{
		whiteMode: f.WhiteMode,
	}
	var rules []FilterItem
	if f.Rules != nil && len(f.Rules) > 0 {
		for _, rule := range f.Rules {
			re, err := newFilterItem(rule)
			if err != nil {
				return nil, err
			}
			rules = append(rules, *re)
		}
	}
	if len(rules) > 0 {
		ff.rules = rules
	}
	return ff, nil
}

func (f *Filter) Filter(list []option.Outbound, tagMap map[string]string) []option.Outbound {
	if f.rules != nil && len(f.rules) > 0 {
		newList := make([]option.Outbound, 0, len(list))
		for _, s := range list {
			match := false
			for _, rule := range f.rules {
				if rule.match(&s, tagMap) {
					match = true
					break
				}
			}
			if f.whiteMode {
				if match {
					newList = append(newList, s)
				}
			} else {
				if !match {
					newList = append(newList, s)
				}
			}
		}
		return newList
	}
	return list
}

type FilterItem struct {
	isTag    bool
	isType   bool
	isServer bool

	regex *regexp2.Regexp
}

func newFilterItem(rule string) (*FilterItem, error) {
	var item FilterItem
	var bRule string
	switch {
	case strings.HasPrefix(rule, "tag:"):
		bRule = strings.TrimPrefix(rule, "tag:")
		item.isTag = true
	case strings.HasPrefix(rule, "type:"):
		bRule = strings.TrimPrefix(rule, "type:")
		item.isType = true
	case strings.HasPrefix(rule, "server:"):
		bRule = strings.TrimPrefix(rule, "server:")
		item.isServer = true
	default:
		bRule = rule
		item.isTag = true
	}
	regex, err := regexp2.Compile(bRule, regexp2.RE2)
	if err != nil {
		return nil, E.Cause(err, "invalid rule: ", rule)
	}
	item.regex = regex
	return &item, nil
}

func (i *FilterItem) match(outbound *option.Outbound, tagMap map[string]string) bool { // append ==> true
	var s string
	if i.isType {
		s = outbound.Type
	} else if i.isServer {
		s = getServer(outbound)
	} else {
		if tagMap != nil {
			s = tagMap[outbound.Tag]
		} else {
			s = outbound.Tag
		}
	}
	b, err := i.regex.MatchString(s)
	return err == nil && b
}

func getServer(outbound *option.Outbound) string {
	var server string
	switch outbound.Type {
	case C.TypeHTTP:
		server = outbound.HTTPOptions.Server
	case C.TypeShadowsocks:
		server = outbound.ShadowsocksOptions.Server
	case C.TypeVMess:
		server = outbound.VMessOptions.Server
	case C.TypeTrojan:
		server = outbound.TrojanOptions.Server
	case C.TypeWireGuard:
		server = outbound.WireGuardOptions.Server
	case C.TypeHysteria:
		server = outbound.HysteriaOptions.Server
	case C.TypeSSH:
		server = outbound.SSHOptions.Server
	case C.TypeShadowTLS:
		server = outbound.ShadowTLSOptions.Server
	case C.TypeShadowsocksR:
		server = outbound.ShadowsocksROptions.Server
	case C.TypeVLESS:
		server = outbound.VLESSOptions.Server
	case C.TypeTUIC:
		server = outbound.TUICOptions.Server
	case C.TypeHysteria2:
		server = outbound.Hysteria2Options.Server
	}
	return server
}

func setServer(outbound *option.Outbound, server string) {
	switch outbound.Type {
	case C.TypeHTTP:
		outbound.HTTPOptions.Server = server
	case C.TypeShadowsocks:
		outbound.ShadowsocksOptions.Server = server
	case C.TypeVMess:
		outbound.VMessOptions.Server = server
	case C.TypeTrojan:
		outbound.TrojanOptions.Server = server
	case C.TypeWireGuard:
		outbound.WireGuardOptions.Server = server
	case C.TypeHysteria:
		outbound.HysteriaOptions.Server = server
	case C.TypeSSH:
		outbound.SSHOptions.Server = server
	case C.TypeShadowTLS:
		outbound.ShadowTLSOptions.Server = server
	case C.TypeShadowsocksR:
		outbound.ShadowsocksROptions.Server = server
	case C.TypeVLESS:
		outbound.VLESSOptions.Server = server
	case C.TypeTUIC:
		outbound.TUICOptions.Server = server
	case C.TypeHysteria2:
		outbound.Hysteria2Options.Server = server
	}
}
