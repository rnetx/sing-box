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

type proxyClashVMess struct {
	proxyClashDefault `yaml:",inline"`
	//
	UUID                string `yaml:"uuid"`
	AlterID             int    `yaml:"alterId"`
	Cipher              string `yaml:"cipher"`
	UDP                 *bool  `yaml:"udp,omitempty"`
	TLS                 bool   `yaml:"tls,omitempty"`
	SkipCertVerify      bool   `yaml:"skip-cert-verify,omitempty"`
	Fingerprint         string `yaml:"fingerprint,omitempty"`
	ClientFingerprint   string `yaml:"client-fingerprint,omitempty"`
	ServerName          string `yaml:"servername,omitempty"`
	PacketEncoding      string `yaml:"packet-encoding,omitempty"`
	GlobalPadding       bool   `yaml:"global-padding,omitempty"`
	AuthenticatedLength bool   `yaml:"authenticated-length,omitempty"`
	//
	Network string `yaml:"network,omitempty"`
	//
	WSOptions    *proxyClashWSOptions    `yaml:"ws-opts,omitempty"`
	HTTPOptions  *proxyClashHTTPOptions  `yaml:"http-opts,omitempty"`
	HTTP2Options *proxyClashHTTP2Options `yaml:"h2-opts,omitempty"`
	GrpcOptions  *proxyClashGrpcOptions  `yaml:"grpc-opts,omitempty"`
	//
	MuxOptions *proxyClashSingMuxOptions `yaml:"smux,omitempty"`
	//
	RealityOptions *proxyClashRealityOptions `yaml:"reality-opts,omitempty"`
}

type ProxyVMess struct {
	tag           string
	clashOptions  *proxyClashVMess
	dialerOptions option.DialerOptions
}

func (p *ProxyVMess) Tag() string {
	if p.tag == "" {
		p.tag = p.clashOptions.Name
	}
	if p.tag == "" {
		p.tag = net.JoinHostPort(p.clashOptions.Server, p.clashOptions.ServerPort.Value)
	}
	return p.tag
}

func (p *ProxyVMess) Type() string {
	return C.TypeVMess
}

func (p *ProxyVMess) SetClashOptions(options any) bool {
	clashOptions, ok := options.(proxyClashVMess)
	if !ok {
		return false
	}
	p.clashOptions = &clashOptions
	return true
}

func (p *ProxyVMess) GetClashType() string {
	return p.clashOptions.Type
}

func (p *ProxyVMess) SetDialerOptions(dialer option.DialerOptions) {
	p.dialerOptions = dialer
}

func (p *ProxyVMess) GenerateOptions() (*option.Outbound, error) {
	serverPort, err := strconv.ParseUint(p.clashOptions.ServerPort.Value, 10, 16)
	if err != nil {
		return nil, E.Cause(err, "fail to parse port")
	}

	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeVMess,
		VMessOptions: option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: uint16(serverPort),
			},
			UUID:                p.clashOptions.UUID,
			Security:            p.clashOptions.Cipher,
			AlterId:             p.clashOptions.AlterID,
			GlobalPadding:       p.clashOptions.GlobalPadding,
			AuthenticatedLength: p.clashOptions.AuthenticatedLength,
			PacketEncoding:      p.clashOptions.PacketEncoding,
			//
			DialerOptions: p.dialerOptions,
		},
	}

	if p.clashOptions.UDP != nil && !*p.clashOptions.UDP {
		opt.VMessOptions.Network = N.NetworkTCP
	}

	switch p.clashOptions.Network {
	case "ws":
		if p.clashOptions.WSOptions == nil {
			p.clashOptions.WSOptions = &proxyClashWSOptions{}
		}

		opt.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                p.clashOptions.WSOptions.Path,
				MaxEarlyData:        uint32(p.clashOptions.WSOptions.MaxEarlyData),
				EarlyDataHeaderName: p.clashOptions.WSOptions.EarlyDataHeaderName,
			},
		}

		opt.VMessOptions.Transport.WebsocketOptions.Headers = make(map[string]option.Listable[string], 0)

		if p.clashOptions.WSOptions.Headers != nil && len(p.clashOptions.WSOptions.Headers) > 0 {
			for k, v := range p.clashOptions.WSOptions.Headers {
				opt.VMessOptions.Transport.WebsocketOptions.Headers[k] = option.Listable[string]{v}
			}
		}

		if opt.VMessOptions.Transport.WebsocketOptions.Headers["Host"] == nil {
			opt.VMessOptions.Transport.WebsocketOptions.Headers["Host"] = option.Listable[string]{p.clashOptions.Server}
		}

		if p.clashOptions.TLS {
			opt.VMessOptions.TLS = &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: p.clashOptions.Server,
				Insecure:   p.clashOptions.SkipCertVerify,
			}

			opt.VMessOptions.TLS.ALPN = []string{"http/1.1"}

			if p.clashOptions.ServerName != "" {
				opt.VMessOptions.TLS.ServerName = p.clashOptions.ServerName
			} else if opt.VMessOptions.Transport.WebsocketOptions.Headers["Host"] != nil {
				opt.VMessOptions.TLS.ServerName = opt.VMessOptions.Transport.WebsocketOptions.Headers["Host"][0]
			}

			if p.clashOptions.ClientFingerprint != "" {
				if !GetTag("with_utls") {
					return nil, E.New(`uTLS is not included in this build, rebuild with -tags with_utls`)
				}

				opt.VMessOptions.TLS.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: p.clashOptions.ClientFingerprint,
				}
			}
		}
	case "http":
		if p.clashOptions.HTTPOptions == nil {
			p.clashOptions.HTTPOptions = &proxyClashHTTPOptions{}
		}

		opt.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method: p.clashOptions.HTTPOptions.Method,
			},
		}

		if p.clashOptions.HTTPOptions.Headers != nil && len(p.clashOptions.HTTPOptions.Headers) > 0 {
			opt.VMessOptions.Transport.HTTPOptions.Headers = make(map[string]option.Listable[string], 0)
			for k, v := range p.clashOptions.HTTPOptions.Headers {
				opt.VMessOptions.Transport.HTTPOptions.Headers[k] = v
			}

			if p.clashOptions.HTTPOptions.Headers["Host"] != nil {
				opt.VMessOptions.Transport.HTTPOptions.Host = p.clashOptions.HTTPOptions.Headers["Host"]
			}

			if p.clashOptions.HTTPOptions.Path != nil {
				opt.VMessOptions.Transport.HTTPOptions.Path = p.clashOptions.HTTPOptions.Path[0]
			}
		}

		if p.clashOptions.TLS {
			opt.VMessOptions.TLS = &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: p.clashOptions.Server,
				Insecure:   p.clashOptions.SkipCertVerify,
			}

			if p.clashOptions.ServerName != "" {
				opt.VMessOptions.TLS.ServerName = p.clashOptions.ServerName
			}

			if p.clashOptions.ClientFingerprint != "" {
				if !GetTag("with_utls") {
					return nil, E.New(`uTLS is not included in this build, rebuild with -tags with_utls`)
				}
				opt.VMessOptions.TLS.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: p.clashOptions.ClientFingerprint,
				}
			}

			if p.clashOptions.RealityOptions != nil {
				opt.VMessOptions.TLS.Reality = &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: p.clashOptions.RealityOptions.PublicKey,
					ShortID:   p.clashOptions.RealityOptions.ShortID,
				}
			}
		}
	case "h2":
		if p.clashOptions.HTTP2Options == nil {
			return nil, E.New("missing h2-opts")
		}

		opt.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: p.clashOptions.HTTP2Options.Host,
				Path: p.clashOptions.HTTP2Options.Path,
			},
		}

		opt.VMessOptions.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: p.clashOptions.Server,
			Insecure:   p.clashOptions.SkipCertVerify,
		}

		opt.VMessOptions.TLS.ALPN = []string{"h2"}

		if p.clashOptions.ServerName != "" {
			opt.VMessOptions.TLS.ServerName = p.clashOptions.ServerName
		}

		if p.clashOptions.ClientFingerprint != "" {
			if !GetTag("with_utls") {
				return nil, E.New(`uTLS is not included in this build, rebuild with -tags with_utls`)
			}
			opt.VMessOptions.TLS.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: p.clashOptions.ClientFingerprint,
			}
		}

		if p.clashOptions.RealityOptions != nil {
			opt.VMessOptions.TLS.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: p.clashOptions.RealityOptions.PublicKey,
				ShortID:   p.clashOptions.RealityOptions.ShortID,
			}
		}
	case "grpc":
		if p.clashOptions.GrpcOptions == nil {
			p.clashOptions.GrpcOptions = &proxyClashGrpcOptions{}
		}

		opt.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: p.clashOptions.GrpcOptions.ServiceName,
			},
		}

		opt.VMessOptions.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			Insecure:   p.clashOptions.SkipCertVerify,
			ServerName: p.clashOptions.Server,
		}

		if p.clashOptions.ServerName != "" {
			opt.VMessOptions.TLS.ServerName = p.clashOptions.ServerName
		}

		if p.clashOptions.ClientFingerprint != "" {
			if !GetTag("with_utls") {
				return nil, E.New(`uTLS is not included in this build, rebuild with -tags with_utls`)
			}
			opt.VMessOptions.TLS.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: p.clashOptions.ClientFingerprint,
			}
		}

		if p.clashOptions.RealityOptions != nil {
			opt.VMessOptions.TLS.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: p.clashOptions.RealityOptions.PublicKey,
				ShortID:   p.clashOptions.RealityOptions.ShortID,
			}
		}
	default:
		if p.clashOptions.TLS {
			opt.VMessOptions.TLS = &option.OutboundTLSOptions{
				Enabled:    true,
				Insecure:   p.clashOptions.SkipCertVerify,
				ServerName: p.clashOptions.Server,
			}

			if p.clashOptions.ServerName != "" {
				opt.VMessOptions.TLS.ServerName = p.clashOptions.ServerName
			}

			if p.clashOptions.ClientFingerprint != "" {
				if !GetTag("with_utls") {
					return nil, E.New(`uTLS is not included in this build, rebuild with -tags with_utls`)
				}
				opt.VMessOptions.TLS.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: p.clashOptions.ClientFingerprint,
				}
			}

			if p.clashOptions.RealityOptions != nil {
				opt.VMessOptions.TLS.Reality = &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: p.clashOptions.RealityOptions.PublicKey,
					ShortID:   p.clashOptions.RealityOptions.ShortID,
				}
			}
		}
	}

	if p.clashOptions.MuxOptions != nil && p.clashOptions.MuxOptions.Enabled {
		opt.VMessOptions.Multiplex = &option.MultiplexOptions{
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
		opt.VMessOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
	case "ipv6":
		opt.VMessOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv6)
	case "ipv4-prefer":
		opt.VMessOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv4)
	case "ipv6-prefer":
		opt.VMessOptions.DialerOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv6)
	default:
	}

	return opt, nil
}
