package proxyprovider

import (
	"strings"

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
