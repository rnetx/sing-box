//go:build with_proxyprovider

package proxy

import (
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type proxyClashSocks struct {
	proxyClashDefault `yaml:",inline"`
	//
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	//
	TLS            bool   `yaml:"tls,omitempty"`
	SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	FingerPrint    string `yaml:"fingerprint,omitempty"`
	//
	UDP *bool `yaml:"udp,omitempty"`
}

type ProxySocks struct {
	tag           string
	clashOptions  *proxyClashSocks
	dialerOptions option.DialerOptions
}

func (p *ProxySocks) Tag() string {
	if p.tag == "" {
		p.tag = p.clashOptions.Name
	}
	if p.tag == "" {
		p.tag = net.JoinHostPort(p.clashOptions.Server, p.clashOptions.ServerPort.Value)
	}
	return p.tag
}

func (p *ProxySocks) Type() string {
	return C.TypeSOCKS
}

func (p *ProxySocks) SetClashOptions(options any) bool {
	clashOptions, ok := options.(proxyClashSocks)
	if !ok {
		return false
	}
	p.clashOptions = &clashOptions
	return true
}

func (p *ProxySocks) GetClashType() string {
	return p.clashOptions.Type
}

func (p *ProxySocks) SetDialerOptions(dialer option.DialerOptions) {
	p.dialerOptions = dialer
}

func (p *ProxySocks) GenerateOptions() (*option.Outbound, error) {
	if p.clashOptions.TLS {
		return nil, E.New("socks5 over tls is not supported in sing-box")
	}

	serverPort, err := strconv.ParseUint(p.clashOptions.ServerPort.Value, 10, 16)
	if err != nil {
		return nil, E.Cause(err, "fail to parse port")
	}

	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeSOCKS,
		SocksOptions: option.SocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: uint16(serverPort),
			},
			Username: p.clashOptions.Username,
			Password: p.clashOptions.Password,
			Version:  "5",
			//
			DialerOptions: p.dialerOptions,
		},
	}

	if p.clashOptions.UDP != nil && !*p.clashOptions.UDP {
		opt.SocksOptions.Network = N.NetworkTCP
	}

	switch p.clashOptions.IPVersion {
	case "dual":
	case "ipv4":
		opt.SocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
	case "ipv6":
		opt.SocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv6)
	case "ipv4-prefer":
		opt.SocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv4)
	case "ipv6-prefer":
		opt.SocksOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv6)
	default:
	}

	return opt, nil
}
