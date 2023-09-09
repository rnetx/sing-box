//go:build with_proxyprovider

package proxy

import (
	"fmt"
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type proxyClashHysteria struct {
	proxyClashDefault `yaml:",inline"`
	//
	Protocol string `yaml:"protocol,omitempty"`
	//
	Up                  *string `yaml:"up,omitempty"`
	Down                *string `yaml:"down,omitempty"`
	Obfs                string  `yaml:"obfs,omitempty"`
	Auth                []byte  `yaml:"auth,omitempty"`
	AuthString          string  `yaml:"auth-str,omitempty"`
	ReceiveWindowConn   uint64  `yaml:"recv-window-conn,omitempty"`
	ReceiveWindow       uint64  `yaml:"recv-window,omitempty"`
	DisableMTUDiscovery bool    `yaml:"disable-mtu-discovery,omitempty"`
	UDP                 *bool   `yaml:"udp,omitempty"`

	SNI               string   `yaml:"sni,omitempty"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify,omitempty"`
	ALPN              []string `yaml:"alpn,omitempty"`
	CustomCA          string   `yaml:"ca,omitempty"`
	CustomCAString    string   `yaml:"ca-str,omitempty"`
	ClientFingerPrint string   `yaml:"client-fingerprint,omitempty"`
	//
	HopInterval int `yaml:"hop-interval,omitempty"`
}

type ProxyHysteria struct {
	tag           string
	clashOptions  *proxyClashHysteria
	dialerOptions option.DialerOptions
}

func (p *ProxyHysteria) Tag() string {
	if p.tag == "" {
		p.tag = p.clashOptions.Name
	}
	if p.tag == "" {
		p.tag = net.JoinHostPort(p.clashOptions.Server, p.clashOptions.ServerPort.Value)
	}
	return p.tag
}

func (p *ProxyHysteria) Type() string {
	return C.TypeHysteria
}

func (p *ProxyHysteria) SetClashOptions(options any) bool {
	clashOptions, ok := options.(proxyClashHysteria)
	if !ok {
		return false
	}
	p.clashOptions = &clashOptions
	return true
}

func (p *ProxyHysteria) GetClashType() string {
	return p.clashOptions.Type
}

func (p *ProxyHysteria) SetDialerOptions(dialer option.DialerOptions) {
	p.dialerOptions = dialer
}

func (p *ProxyHysteria) GenerateOptions() (*option.Outbound, error) {
	if !GetTag("with_quic") {
		return nil, E.New(`quic is not included in this build, rebuild with -tags with_quic`)
	}

	if p.clashOptions.Protocol != "" && p.clashOptions.Protocol != "udp" {
		return nil, E.New("Protocol", p.clashOptions.Protocol, " field in hysteria is not supported in sing-box")
	}

	//	if p.clashOptions.HopInterval != 0 {
	//		return nil, E.New("hop-interval field in hysteria is not supported in sing-box")
	//	}

	serverPort, err := strconv.ParseUint(p.clashOptions.ServerPort.Value, 10, 16)
	if err != nil {
		return nil, E.Cause(err, "fail to parse port")
	}

	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeHysteria,
		HysteriaOptions: option.HysteriaOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: uint16(serverPort),
			},
			Obfs:                p.clashOptions.Obfs,
			Auth:                p.clashOptions.Auth,
			AuthString:          p.clashOptions.AuthString,
			DisableMTUDiscovery: p.clashOptions.DisableMTUDiscovery,
			//
			DialerOptions: p.dialerOptions,
		},
	}

	if p.clashOptions.Up != nil && *p.clashOptions.Up != "" && p.clashOptions.Down != nil && *p.clashOptions.Down != "" {
		if v, err := strconv.Atoi(*p.clashOptions.Up); err == nil {
			*p.clashOptions.Up = fmt.Sprintf("%d Mbps", v)
		}
		if v, err := strconv.Atoi(*p.clashOptions.Down); err == nil {
			*p.clashOptions.Down = fmt.Sprintf("%d Mbps", v)
		}
		opt.HysteriaOptions.Up = *p.clashOptions.Up
		opt.HysteriaOptions.Down = *p.clashOptions.Down
	} else {
		return nil, E.Cause(nil, "missing up and down fields")
	}

	if p.clashOptions.ReceiveWindowConn != 0 {
		opt.HysteriaOptions.ReceiveWindowConn = p.clashOptions.ReceiveWindowConn
	}

	if p.clashOptions.ReceiveWindow != 0 {
		opt.HysteriaOptions.ReceiveWindow = p.clashOptions.ReceiveWindow
	}

	if p.clashOptions.UDP != nil && !*p.clashOptions.UDP {
		opt.HysteriaOptions.Network = N.NetworkTCP
	}

	opt.HysteriaOptions.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: p.clashOptions.SNI,
		Insecure:   p.clashOptions.SkipCertVerify,
	}

	if p.clashOptions.ALPN != nil {
		opt.HysteriaOptions.TLS.ALPN = p.clashOptions.ALPN
	}

	if p.clashOptions.CustomCA != "" {
		opt.HysteriaOptions.TLS.CertificatePath = p.clashOptions.CustomCA
	}

	if p.clashOptions.CustomCAString != "" {
		opt.HysteriaOptions.TLS.Certificate = p.clashOptions.CustomCAString
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
