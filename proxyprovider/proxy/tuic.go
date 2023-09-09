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

type proxyClashTUIC struct {
	proxyClashDefault `yaml:",inline"`
	//
	UUID                 string `yaml:"uuid"`
	Password             string `yaml:"password,omitempty"`
	CongestionController string `yaml:"congestion-controller,omitempty"`
	UdpRelayMode         string `yaml:"udp-relay-mode,omitempty"`
	UDPOverStream        bool   `yaml:"udp-over-stream,omitempty"`
	ReduceRtt            bool   `yaml:"reduce-rtt,omitempty"`
	HeartbeatInterval    int    `yaml:"heartbeat-interval,omitempty"`
	UDP                  *bool  `yaml:"udp,omitempty"`

	SNI               string   `yaml:"sni,omitempty"`
	DisableSni        bool     `yaml:"disable-sni,omitempty"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify,omitempty"`
	ALPN              []string `yaml:"alpn,omitempty"`
	CustomCA          string   `yaml:"ca,omitempty"`
	CustomCAString    string   `yaml:"ca-str,omitempty"`
	ClientFingerPrint string   `yaml:"client-fingerprint,omitempty"`
}

type ProxyTUIC struct {
	tag           string
	clashOptions  *proxyClashTUIC
	dialerOptions option.DialerOptions
}

func (p *ProxyTUIC) Tag() string {
	if p.tag == "" {
		p.tag = p.clashOptions.Name
	}
	if p.tag == "" {
		p.tag = net.JoinHostPort(p.clashOptions.Server, p.clashOptions.ServerPort.Value)
	}
	return p.tag
}

func (p *ProxyTUIC) Type() string {
	return C.TypeTUIC
}

func (p *ProxyTUIC) SetClashOptions(options any) bool {
	clashOptions, ok := options.(proxyClashTUIC)
	if !ok {
		return false
	}
	p.clashOptions = &clashOptions
	return true
}

func (p *ProxyTUIC) GetClashType() string {
	return p.clashOptions.Type
}

func (p *ProxyTUIC) SetDialerOptions(dialer option.DialerOptions) {
	p.dialerOptions = dialer
}

func (p *ProxyTUIC) GenerateOptions() (*option.Outbound, error) {
	if !GetTag("with_quic") {
		return nil, E.New(`quic is not included in this build, rebuild with -tags with_quic`)
	}

	serverPort, err := strconv.ParseUint(p.clashOptions.ServerPort.Value, 10, 16)
	if err != nil {
		return nil, E.Cause(err, "fail to parse port")
	}

	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeTUIC,
		TUICOptions: option.TUICOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: uint16(serverPort),
			},
			UUID:              p.clashOptions.UUID,
			Password:          p.clashOptions.Password,
			CongestionControl: p.clashOptions.CongestionController,
			UDPRelayMode:      p.clashOptions.UdpRelayMode,
			UDPOverStream:     p.clashOptions.UDPOverStream,
			ZeroRTTHandshake:  p.clashOptions.ReduceRtt,
			Heartbeat:         option.Duration(p.clashOptions.HeartbeatInterval),
			//
			DialerOptions: p.dialerOptions,
		},
	}

	if p.clashOptions.UDP != nil && !*p.clashOptions.UDP {
		opt.TUICOptions.Network = N.NetworkTCP
	}

	opt.TUICOptions.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: p.clashOptions.SNI,
		DisableSNI: p.clashOptions.DisableSni,
		Insecure:   p.clashOptions.SkipCertVerify,
	}

	if p.clashOptions.ALPN != nil {
		opt.TUICOptions.TLS.ALPN = p.clashOptions.ALPN
	}

	if p.clashOptions.CustomCA != "" {
		opt.TUICOptions.TLS.CertificatePath = p.clashOptions.CustomCA
	}

	if p.clashOptions.CustomCAString != "" {
		opt.TUICOptions.TLS.Certificate = p.clashOptions.CustomCAString
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
