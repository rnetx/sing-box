//go:build with_proxyprovider && with_shadowsocksr

package proxy

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	N "github.com/sagernet/sing/common/network"
)

func (p *ProxyShadowsocksR) GenerateOptions() (*option.Outbound, error) {
	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeShadowsocksR,
		ShadowsocksROptions: option.ShadowsocksROutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: p.clashOptions.ServerPort,
			},
			Method:        p.clashOptions.Cipher,
			Password:      p.clashOptions.Password,
			Obfs:          p.clashOptions.Obfs,
			ObfsParam:     p.clashOptions.ObfsParam,
			Protocol:      p.clashOptions.Protocol,
			ProtocolParam: p.clashOptions.ProtocolParam,
			//
			DialerOptions: p.dialerOptions,
		},
	}

	if !p.clashOptions.UDP {
		opt.ShadowsocksROptions.Network = N.NetworkTCP
	}

	switch p.clashOptions.IPVersion {
	case "dual":
	case "ipv4":
		opt.ShadowsocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
	case "ipv6":
		opt.ShadowsocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv6)
	case "ipv4-prefer":
		opt.ShadowsocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv4)
	case "ipv6-prefer":
		opt.ShadowsocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv6)
	default:
	}

	return opt, nil
}
