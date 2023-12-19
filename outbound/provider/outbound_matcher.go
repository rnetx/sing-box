package provider

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type ruleMatcher interface {
	match(*option.Outbound) bool
}

type tagMatcher regexp.Regexp

func (m *tagMatcher) match(options *option.Outbound) bool {
	return (*regexp.Regexp)(m).MatchString(options.Tag)
}

type typeMatcher string

func (m typeMatcher) match(options *option.Outbound) bool {
	return string(m) == options.Type
}

type OutboundMatcher struct {
	rules []ruleMatcher
}

func NewOutboundMatcher(rules []string) (*OutboundMatcher, error) {
	if len(rules) == 0 {
		return nil, E.New("missing rules")
	}
	o := &OutboundMatcher{
		rules: make([]ruleMatcher, 0, len(rules)),
	}
	for _, rule := range rules {
		switch {
		case strings.HasPrefix(rule, "tag:"):
			item := string(rule[4:])
			re, err := regexp.Compile(item)
			if err != nil {
				return nil, E.Cause(err, "invalid rule: ", rule)
			}
			o.rules = append(o.rules, (*tagMatcher)(re))
		case strings.HasPrefix(rule, "type:"):
			item := string(rule[5:])
			o.rules = append(o.rules, typeMatcher(item))
		default:
			re, err := regexp.Compile(rule)
			if err != nil {
				return nil, E.Cause(err, "invalid rule: ", rule)
			}
			o.rules = append(o.rules, (*tagMatcher)(re))
		}
	}
	return o, nil
}

func (o *OutboundMatcher) Match(options *option.Outbound) bool {
	for _, rule := range o.rules {
		if rule.match(options) {
			return true
		}
	}
	return false
}
