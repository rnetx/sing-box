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

type proxyClashTrojan struct {
	proxyClashDefault `yaml:",inline"`
	//
	Password string `yaml:"password,omitempty"`
	//
	ALPN              []string `yaml:"alpn,omitempty"`
	ServerName        string   `yaml:"sni,omitempty"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify,omitempty"`
	FingerPrint       string   `yaml:"fingerprint,omitempty"`
	ClientFingerPrint string   `yaml:"client-fingerprint,omitempty"`
	//
	UDP *bool `yaml:"udp,omitempty"`
	//
	Network     string                 `yaml:"network,omitempty"`
	Flow        string                 `yaml:"flow,omitempty"`
	FlowShow    bool                   `yaml:"flow-show,omitempty"`
	GrpcOptions *proxyClashGrpcOptions `yaml:"grpc-opts,omitempty"`
	WSOptions   *proxyClashWSOptions   `yaml:"ws-opts,omitempty"`
	//
	MuxOptions *proxyClashSingMuxOptions `yaml:"smux,omitempty"`
	//
	RealityOptions *proxyClashRealityOptions `yaml:"reality-opts,omitempty"`
}

type ProxyTrojan struct {
	tag           string
	clashOptions  *proxyClashTrojan
	dialerOptions option.DialerOptions
}

func (p *ProxyTrojan) Tag() string {
	if p.tag == "" {
		p.tag = p.clashOptions.Name
	}
	if p.tag == "" {
		p.tag = net.JoinHostPort(p.clashOptions.Server, p.clashOptions.ServerPort.Value)
	}
	return p.tag
}

func (p *ProxyTrojan) Type() string {
	return C.TypeTrojan
}

func (p *ProxyTrojan) SetClashOptions(options any) bool {
	clashOptions, ok := options.(proxyClashTrojan)
	if !ok {
		return false
	}
	p.clashOptions = &clashOptions
	return true
}

func (p *ProxyTrojan) GetClashType() string {
	return p.clashOptions.Type
}

func (p *ProxyTrojan) SetDialerOptions(dialer option.DialerOptions) {
	p.dialerOptions = dialer
}

func (p *ProxyTrojan) GenerateOptions() (*option.Outbound, error) {
	if p.clashOptions.Flow != "" || p.clashOptions.FlowShow {
		return nil, E.New("trojan flow is not supported in sing-box")
	}

	serverPort, err := strconv.ParseUint(p.clashOptions.ServerPort.Value, 10, 16)
	if err != nil {
		return nil, E.Cause(err, "fail to parse port")
	}

	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeTrojan,
		TrojanOptions: option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: uint16(serverPort),
			},
			Password: p.clashOptions.Password,
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: p.clashOptions.Server,
				Insecure:   p.clashOptions.SkipCertVerify,
				ALPN:       p.clashOptions.ALPN,
			},
			//
			DialerOptions: p.dialerOptions,
		},
	}

	if p.clashOptions.ServerName != "" {
		opt.TrojanOptions.TLS.ServerName = p.clashOptions.ServerName
	}

	if p.clashOptions.ClientFingerPrint != "" {
		if !GetTag("with_utls") {
			return nil, E.New(`uTLS is not included in this build, rebuild with -tags with_utls`)
		}

		opt.TrojanOptions.TLS.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: p.clashOptions.ClientFingerPrint,
		}
	}

	if p.clashOptions.UDP != nil && !*p.clashOptions.UDP {
		opt.TrojanOptions.Network = N.NetworkTCP
	}

	switch p.clashOptions.Network {
	case "ws":
		if p.clashOptions.WSOptions == nil {
			p.clashOptions.WSOptions = &proxyClashWSOptions{}
		}

		opt.TrojanOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                p.clashOptions.WSOptions.Path,
				MaxEarlyData:        uint32(p.clashOptions.WSOptions.MaxEarlyData),
				EarlyDataHeaderName: p.clashOptions.WSOptions.EarlyDataHeaderName,
			},
		}

		opt.TrojanOptions.Transport.WebsocketOptions.Headers = make(map[string]option.Listable[string], 0)

		if p.clashOptions.WSOptions.Headers != nil && len(p.clashOptions.WSOptions.Headers) > 0 {
			for k, v := range p.clashOptions.WSOptions.Headers {
				opt.TrojanOptions.Transport.WebsocketOptions.Headers[k] = option.Listable[string]{v}
			}
		}

		if opt.TrojanOptions.Transport.WebsocketOptions.Headers["Host"] == nil {
			opt.TrojanOptions.Transport.WebsocketOptions.Headers["Host"] = option.Listable[string]{opt.TrojanOptions.TLS.ServerName}
		}
	case "grpc":
		if p.clashOptions.GrpcOptions == nil {
			p.clashOptions.GrpcOptions = &proxyClashGrpcOptions{}
		}

		opt.TrojanOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: p.clashOptions.GrpcOptions.ServiceName,
			},
		}
	}

	if p.clashOptions.MuxOptions != nil && p.clashOptions.MuxOptions.Enabled {
		opt.TrojanOptions.Multiplex = &option.MultiplexOptions{
			Enabled:        true,
			Protocol:       p.clashOptions.MuxOptions.Protocol,
			MaxConnections: p.clashOptions.MuxOptions.MaxConnections,
			MaxStreams:     p.clashOptions.MuxOptions.MaxStreams,
			MinStreams:     p.clashOptions.MuxOptions.MinStreams,
			Padding:        p.clashOptions.MuxOptions.Padding,
		}
	}

	switch p.clashOptions.IPVersion {
	case "dual":
	case "ipv4":
		opt.TrojanOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
	case "ipv6":
		opt.TrojanOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv6)
	case "ipv4-prefer":
		opt.TrojanOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv4)
	case "ipv6-prefer":
		opt.TrojanOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv6)
	default:
	}

	return opt, nil
}
