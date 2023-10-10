package clash

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

type ClashBasicRule struct {
	Network       []string `json:"network,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	Geosite       []string `json:"geosite,omitempty"`
	GeoIP         []string `json:"geoip,omitempty"` // only route rule
	SourceIPCIDR  []string `json:"source_ip_cidr,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"` // only route rule
	SourcePort    []uint16 `json:"source_port,omitempty"`
	Port          []uint16 `json:"port,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
}

func (r *ClashBasicRule) insertRule(globalRule, rule string) error {
	ms := strings.SplitN(rule, ",", 2)
	if len(ms) != 2 {
		return fmt.Errorf("invalid rule: %s", rule)
	}
	if ms[0] == "" || ms[1] == "" {
		return fmt.Errorf("invalid rule: %s", rule)
	}
	mType := ms[0]
	switch mType {
	case "DOMAIN":
		r.Domain = append(r.Domain, ms[1])
	case "DOMAIN-SUFFIX":
		mRule := ms[1]
		switch {
		case strings.HasPrefix(mRule, "+"):
			r.DomainSuffix = append(r.DomainSuffix, mRule[1:])
		case strings.HasPrefix(mRule, "*"):
			r.DomainSuffix = append(r.DomainSuffix, mRule[1:])
		case strings.Index(mRule, "*") > 0:
			return fmt.Errorf("invalid rule: %s", globalRule)
		default:
			r.DomainSuffix = append(r.DomainSuffix, mRule)
		}
	case "DOMAIN-KEYWORD":
		r.DomainKeyword = append(r.DomainKeyword, ms[1])
	case "GEOSITE":
		r.Geosite = append(r.Geosite, strings.ToLower(ms[1]))
	case "GEOIP":
		r.GeoIP = append(r.GeoIP, strings.ToLower(ms[1]))
	case "IP-CIDR", "IP-CIDR6":
		mRule := ms[1]
		mRule = strings.TrimSuffix(mRule, ",no-resolve")
		var addr string
		prefix, err := netip.ParsePrefix(mRule)
		if err != nil {
			ip, err := netip.ParseAddr(mRule)
			if err != nil {
				return fmt.Errorf("invalid rule: %s", rule)
			}
			addr = ip.String()
		} else {
			addr = prefix.String()
		}
		r.IPCIDR = append(r.IPCIDR, addr)
	case "SRC-IP-CIDR":
		mRule := ms[1]
		mRule = strings.TrimPrefix(mRule, ",no-resolve")
		var addr string
		prefix, err := netip.ParsePrefix(mRule)
		if err != nil {
			ip, err := netip.ParseAddr(mRule)
			if err != nil {
				return fmt.Errorf("invalid rule: %s", rule)
			}
			addr = ip.String()
		} else {
			addr = prefix.String()
		}
		r.SourceIPCIDR = append(r.SourceIPCIDR, addr)
	case "SRC-PORT", "DST-PORT":
		portUint16, err := strconv.ParseUint(ms[1], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid rule: %s", globalRule)
		}
		if portUint16 == 0 || portUint16 > 0xffff {
			return fmt.Errorf("invalid rule: %s", globalRule)
		}
		if mType == "DST-PORT" {
			r.Port = append(r.Port, uint16(portUint16))
		} else {
			r.SourcePort = append(r.SourcePort, uint16(portUint16))
		}
	case "PROCESS-NAME":
		r.ProcessName = append(r.ProcessName, ms[1])
	case "PROCESS-PATH":
		r.ProcessPath = append(r.ProcessPath, ms[1])
	case "NETWORK":
		r.Network = append(r.Network, strings.ToLower(ms[1]))
	default:
		return fmt.Errorf("invalid rule: %s", globalRule)
	}
	return nil
}

func (r *ClashBasicRule) insertDomainRule(rule string) error {
	switch {
	case strings.HasPrefix(rule, "*."):
		rule = strings.TrimPrefix(rule, "*")
		r.DomainSuffix = append(r.DomainSuffix, rule)
	case strings.HasPrefix(rule, "+."):
		rule = strings.TrimPrefix(rule, "+")
		r.DomainSuffix = append(r.DomainSuffix, rule)
	case strings.HasPrefix(rule, "."):
		r.DomainSuffix = append(r.DomainSuffix, rule)
	case strings.Index(rule, "*") > 0:
		return fmt.Errorf("invalid rule: %s", rule)
	default:
		r.Domain = append(r.Domain, rule)
		r.DomainSuffix = append(r.DomainSuffix, rule)
	}
	return nil
}

func (r *ClashBasicRule) insertIPCIDRRule(rule string) error {
	var addr string
	prefix, err := netip.ParsePrefix(rule)
	if err != nil {
		ip, err := netip.ParseAddr(rule)
		if err != nil {
			return fmt.Errorf("invalid rule: %s", rule)
		}
		addr = ip.String()
	} else {
		addr = prefix.String()
	}
	r.IPCIDR = append(r.IPCIDR, addr)
	return nil
}

func (r *ClashBasicRule) appendRouteRuleToOptions(basicRule *option.DefaultRule) {
	if r.Network != nil && len(r.Network) > 0 {
		basicRule.Network = AppendSlice[string](basicRule.Network, r.Network...)
	}
	if r.Domain != nil && len(r.Domain) > 0 {
		basicRule.Domain = AppendSlice[string](basicRule.Domain, r.Domain...)
	}
	if r.DomainSuffix != nil && len(r.DomainSuffix) > 0 {
		basicRule.DomainSuffix = AppendSlice[string](basicRule.DomainSuffix, r.DomainSuffix...)
	}
	if r.DomainKeyword != nil && len(r.DomainKeyword) > 0 {
		basicRule.DomainKeyword = AppendSlice[string](basicRule.DomainKeyword, r.DomainKeyword...)
	}
	if r.Geosite != nil && len(r.Geosite) > 0 {
		basicRule.Geosite = AppendSlice[string](basicRule.Geosite, r.Geosite...)
	}
	if r.GeoIP != nil && len(r.GeoIP) > 0 {
		basicRule.GeoIP = AppendSlice[string](basicRule.GeoIP, r.GeoIP...)
	}
	if r.SourceIPCIDR != nil && len(r.SourceIPCIDR) > 0 {
		basicRule.SourceIPCIDR = AppendSlice[string](basicRule.SourceIPCIDR, r.SourceIPCIDR...)
	}
	if r.IPCIDR != nil && len(r.IPCIDR) > 0 {
		basicRule.IPCIDR = AppendSlice[string](basicRule.IPCIDR, r.IPCIDR...)
	}
	if r.SourcePort != nil && len(r.SourcePort) > 0 {
		basicRule.SourcePort = AppendSlice[uint16](basicRule.SourcePort, r.SourcePort...)
	}
	if r.Port != nil && len(r.Port) > 0 {
		basicRule.Port = AppendSlice[uint16](basicRule.Port, r.Port...)
	}
	if r.ProcessName != nil && len(r.ProcessName) > 0 {
		basicRule.ProcessName = AppendSlice[string](basicRule.ProcessName, r.ProcessName...)
	}
	if r.ProcessPath != nil && len(r.ProcessPath) > 0 {
		basicRule.ProcessPath = AppendSlice[string](basicRule.ProcessPath, r.ProcessPath...)
	}
}

func (r *ClashBasicRule) appendDNSRuleToOptions(basicRule *option.DefaultDNSRule) {
	if r.Network != nil && len(r.Network) > 0 {
		basicRule.Network = AppendSlice[string](basicRule.Network, r.Network...)
	}
	if r.Domain != nil && len(r.Domain) > 0 {
		basicRule.Domain = AppendSlice[string](basicRule.Domain, r.Domain...)
	}
	if r.DomainSuffix != nil && len(r.DomainSuffix) > 0 {
		basicRule.DomainSuffix = AppendSlice[string](basicRule.DomainSuffix, r.DomainSuffix...)
	}
	if r.DomainKeyword != nil && len(r.DomainKeyword) > 0 {
		basicRule.DomainKeyword = AppendSlice[string](basicRule.DomainKeyword, r.DomainKeyword...)
	}
	if r.Geosite != nil && len(r.Geosite) > 0 {
		basicRule.Geosite = AppendSlice[string](basicRule.Geosite, r.Geosite...)
	}
	if r.SourceIPCIDR != nil && len(r.SourceIPCIDR) > 0 {
		basicRule.SourceIPCIDR = AppendSlice[string](basicRule.SourceIPCIDR, r.SourceIPCIDR...)
	}
	if r.SourcePort != nil && len(r.SourcePort) > 0 {
		basicRule.SourcePort = AppendSlice[uint16](basicRule.SourcePort, r.SourcePort...)
	}
	if r.Port != nil && len(r.Port) > 0 {
		basicRule.Port = AppendSlice[uint16](basicRule.Port, r.Port...)
	}
	if r.ProcessName != nil && len(r.ProcessName) > 0 {
		basicRule.ProcessName = AppendSlice[string](basicRule.ProcessName, r.ProcessName...)
	}
	if r.ProcessPath != nil && len(r.ProcessPath) > 0 {
		basicRule.ProcessPath = AppendSlice[string](basicRule.ProcessPath, r.ProcessPath...)
	}
}

type Logical string

const (
	LogicalOr  Logical = "or"
	LogicalAnd Logical = "and"
	LogicalNot Logical = "not"
)

type ClashLogicalRule struct {
	Rules   []ClashBasicRule `json:"rules"`
	Logical Logical          `json:"logical"`
}

type ClashRuleSet struct {
	Count        int                `json:"count"`
	BasicRule    *ClashBasicRule    `json:"basic_rule"`
	LogicalRules []ClashLogicalRule `json:"logical_rules"`
}

func NewClashRuleSet() *ClashRuleSet {
	return &ClashRuleSet{}
}

func (r *ClashRuleSet) GetCount() int {
	return r.Count
}

func (r *ClashRuleSet) initBasicRule() {
	if r.BasicRule == nil {
		r.BasicRule = &ClashBasicRule{}
	}
}

func (r *ClashRuleSet) InsertRule(rule string) error {
	ms := strings.SplitN(rule, ",", 2)
	if len(ms) != 2 {
		return fmt.Errorf("invalid rule: %s", rule)
	}
	mType := ms[0]
	switch mType {
	case "AND", "OR", "NOT":
		mRule := ms[1]
		if len(mRule) == 0 {
			return fmt.Errorf("invalid rule: %s", rule)
		}
		bStack := NewStack[rune]()
		rStack := NewStack[rune]()
		LRule := &ClashLogicalRule{}
		for _, c := range mRule {
			switch c {
			case '(':
				bStack.Push(c)
			case ')':
				if bStack.Pop() != '(' {
					return fmt.Errorf("invalid rule: %s", rule)
				}
				d := rStack.PopData()
				if len(d) == 0 {
					return fmt.Errorf("invalid rule: %s", rule)
				}
				str := string(d)
				basicRule := &ClashBasicRule{}
				err := basicRule.insertRule(rule, str)
				if err != nil {
					return err
				}
				LRule.Rules = append(LRule.Rules, *basicRule)
			case ',':
				if rStack.Len() > 0 {
					rStack.Push(c)
				}
			case ' ':
				if rStack.Len() > 0 {
					rStack.Push(c)
				}
			default:
				rStack.Push(c)
			}
		}
		switch mType {
		case "AND":
			LRule.Logical = LogicalAnd
		case "OR":
			LRule.Logical = LogicalOr
		case "NOT":
			LRule.Logical = LogicalNot
		}
		r.LogicalRules = append(r.LogicalRules, *LRule)
		r.Count++
	default:
		r.initBasicRule()
		err := r.BasicRule.insertRule(rule, rule)
		if err != nil {
			return err
		}
		r.Count++
	}
	return nil
}

func (r *ClashRuleSet) InsertDomainRule(rule string) error {
	r.initBasicRule()
	err := r.BasicRule.insertDomainRule(rule)
	if err != nil {
		return err
	}
	r.Count++
	return nil
}

func (r *ClashRuleSet) InsertIPCIDRRule(rule string) error {
	r.initBasicRule()
	err := r.BasicRule.insertIPCIDRRule(rule)
	if err != nil {
		return err
	}
	r.Count++
	return nil
}

func (r *ClashRuleSet) AppendRouteRuleToOptions(rule *option.Rule) ([]option.Rule, error) {
	if rule.Type == C.RuleTypeLogical {
		return nil, fmt.Errorf("logical rule is not supported")
	}
	finalRules := make([]option.Rule, 0, len(r.LogicalRules)+1)
	if r.BasicRule != nil {
		rule := CloneDefaultRule(&rule.DefaultOptions)
		r.BasicRule.appendRouteRuleToOptions(&rule)
		finalRules = append(finalRules, option.Rule{
			Type:           C.RuleTypeDefault,
			DefaultOptions: rule,
		})
	}
	if len(r.LogicalRules) > 0 {
		for _, rRule := range r.LogicalRules {
			logicalDefaultRules := make([]option.DefaultRule, len(rRule.Rules))
			for i, basicRule := range rRule.Rules {
				rule := CloneDefaultRule(&rule.DefaultOptions)
				basicRule.appendRouteRuleToOptions(&rule)
				rule.Outbound = ""
				logicalDefaultRules[i] = rule
			}
			logicalRule := &option.Rule{
				Type: C.RuleTypeLogical,
				LogicalOptions: option.LogicalRule{
					Rules:    logicalDefaultRules,
					Outbound: rule.DefaultOptions.Outbound,
				},
			}
			switch rRule.Logical {
			case LogicalAnd:
				logicalRule.LogicalOptions.Mode = C.LogicalTypeAnd
			case LogicalOr:
				logicalRule.LogicalOptions.Mode = C.LogicalTypeOr
			case LogicalNot:
				logicalRule.LogicalOptions.Mode = C.LogicalTypeOr
				logicalRule.LogicalOptions.Invert = true
			}
			finalRules = append(finalRules, *logicalRule)
		}
	}
	return finalRules, nil
}

func (r *ClashRuleSet) AppendDNSRuleToOptions(rule *option.DNSRule) ([]option.DNSRule, error) {
	if rule.Type == C.RuleTypeLogical {
		return nil, fmt.Errorf("logical rule is not supported")
	}
	finalRules := make([]option.DNSRule, 0, len(r.LogicalRules)+1)
	if r.BasicRule != nil {
		rule := CloneDefaultDNSRule(&rule.DefaultOptions)
		r.BasicRule.appendDNSRuleToOptions(&rule)
		finalRules = append(finalRules, option.DNSRule{
			Type:           C.RuleTypeDefault,
			DefaultOptions: rule,
		})
	}
	if len(r.LogicalRules) > 0 {
		for _, rRule := range r.LogicalRules {
			logicalDefaultRules := make([]option.DefaultDNSRule, len(rRule.Rules))
			for i, basicRule := range rRule.Rules {
				rule := CloneDefaultDNSRule(&rule.DefaultOptions)
				basicRule.appendDNSRuleToOptions(&rule)
				rule.Server = ""
				logicalDefaultRules[i] = rule
			}
			logicalRule := &option.DNSRule{
				Type: C.RuleTypeLogical,
				LogicalOptions: option.LogicalDNSRule{
					Rules:  logicalDefaultRules,
					Server: rule.DefaultOptions.Server,
				},
			}
			switch rRule.Logical {
			case LogicalAnd:
				logicalRule.LogicalOptions.Mode = C.LogicalTypeAnd
			case LogicalOr:
				logicalRule.LogicalOptions.Mode = C.LogicalTypeOr
			case LogicalNot:
				logicalRule.LogicalOptions.Mode = C.LogicalTypeOr
				logicalRule.LogicalOptions.Invert = true
			}
			finalRules = append(finalRules, *logicalRule)
		}
	}
	return finalRules, nil
}

type YamlRule struct {
	Payload []string `yaml:"payload"`
}

func AppendSlice[T comparable](basic []T, list ...T) []T {
	if len(list) > 0 {
		basic = append(basic, list...)
	}
	m := make(map[T]bool)
	for _, n := range basic {
		m[n] = true
	}
	basic = common.Filter[T](basic, func(it T) bool {
		v := m[it]
		if v {
			m[it] = false
		}
		return v
	})
	return basic
}

func CloneDefaultRule(rule *option.DefaultRule) option.DefaultRule {
	var newRule option.DefaultRule
	copy(newRule.Inbound, rule.Inbound)
	newRule.IPVersion = rule.IPVersion
	copy(newRule.Network, rule.Network)
	copy(newRule.AuthUser, rule.AuthUser)
	copy(newRule.Protocol, rule.Protocol)
	copy(newRule.Domain, rule.Domain)
	copy(newRule.DomainSuffix, rule.DomainSuffix)
	copy(newRule.DomainKeyword, rule.DomainKeyword)
	copy(newRule.DomainRegex, rule.DomainRegex)
	copy(newRule.Geosite, rule.Geosite)
	copy(newRule.SourceGeoIP, rule.SourceGeoIP)
	copy(newRule.GeoIP, rule.GeoIP)
	copy(newRule.SourceIPCIDR, rule.SourceIPCIDR)
	copy(newRule.IPCIDR, rule.IPCIDR)
	copy(newRule.SourcePort, rule.SourcePort)
	copy(newRule.SourcePortRange, rule.SourcePortRange)
	copy(newRule.Port, rule.Port)
	copy(newRule.PortRange, rule.PortRange)
	copy(newRule.ProcessName, rule.ProcessName)
	copy(newRule.ProcessPath, rule.ProcessPath)
	copy(newRule.PackageName, rule.PackageName)
	copy(newRule.User, rule.User)
	copy(newRule.UserID, rule.UserID)
	newRule.ClashMode = rule.ClashMode
	newRule.Invert = rule.Invert
	newRule.Outbound = rule.Outbound
	return newRule
}

func CloneDefaultDNSRule(rule *option.DefaultDNSRule) option.DefaultDNSRule {
	var newRule option.DefaultDNSRule
	copy(newRule.Inbound, rule.Inbound)
	newRule.IPVersion = rule.IPVersion
	copy(newRule.Network, rule.Network)
	copy(newRule.AuthUser, rule.AuthUser)
	copy(newRule.Protocol, rule.Protocol)
	copy(newRule.Domain, rule.Domain)
	copy(newRule.DomainSuffix, rule.DomainSuffix)
	copy(newRule.DomainKeyword, rule.DomainKeyword)
	copy(newRule.DomainRegex, rule.DomainRegex)
	copy(newRule.Geosite, rule.Geosite)
	copy(newRule.SourceGeoIP, rule.SourceGeoIP)
	copy(newRule.SourceIPCIDR, rule.SourceIPCIDR)
	copy(newRule.SourcePort, rule.SourcePort)
	copy(newRule.SourcePortRange, rule.SourcePortRange)
	copy(newRule.Port, rule.Port)
	copy(newRule.PortRange, rule.PortRange)
	copy(newRule.ProcessName, rule.ProcessName)
	copy(newRule.ProcessPath, rule.ProcessPath)
	copy(newRule.PackageName, rule.PackageName)
	copy(newRule.User, rule.User)
	copy(newRule.UserID, rule.UserID)
	newRule.ClashMode = rule.ClashMode
	newRule.Invert = rule.Invert
	copy(newRule.Outbound, rule.Outbound)
	newRule.Server = rule.Server
	newRule.DisableCache = rule.DisableCache
	newRule.RewriteTTL = new(uint32)
	*newRule.RewriteTTL = *rule.RewriteTTL
	return newRule
}
