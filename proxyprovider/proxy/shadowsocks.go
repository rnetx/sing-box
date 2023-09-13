//go:build with_proxyprovider

package proxy

import (
	"bytes"
	"net"
	"sort"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"github.com/Dreamacro/clash/common/structure"
)

type proxyClashShadowsocks struct {
	proxyClashDefault `yaml:",inline"`
	//
	Cipher   string `yaml:"cipher,omitempty"`
	Password string `yaml:"password,omitempty"`
	//
	Plugin            string         `yaml:"plugin,omitempty"`
	PluginOpts        map[string]any `yaml:"plugin-opts,omitempty"`
	UDP               *bool          `yaml:"udp,omitempty"`
	UDPOverTCP        bool           `yaml:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion uint8          `yaml:"udp-over-tcp-version,omitempty"`
}

type ProxyShadowsocks struct {
	tag           string
	clashOptions  *proxyClashShadowsocks
	dialerOptions option.DialerOptions
}

func (p *ProxyShadowsocks) Tag() string {
	if p.tag == "" {
		p.tag = p.clashOptions.Name
	}
	if p.tag == "" {
		p.tag = net.JoinHostPort(p.clashOptions.Server, p.clashOptions.ServerPort.Value)
	}
	return p.tag
}

func (p *ProxyShadowsocks) Type() string {
	return C.TypeShadowsocks
}

func (p *ProxyShadowsocks) SetClashOptions(options any) bool {
	clashOptions, ok := options.(proxyClashShadowsocks)
	if !ok {
		return false
	}
	p.clashOptions = &clashOptions
	return true
}

func (p *ProxyShadowsocks) GetClashType() string {
	return p.clashOptions.Type
}

func (p *ProxyShadowsocks) SetDialerOptions(dialer option.DialerOptions) {
	p.dialerOptions = dialer
}

func (p *ProxyShadowsocks) GenerateOptions() (*option.Outbound, error) {
	if !p.checkMethod() {
		return nil, E.New("shadowsocks cipher: ", p.clashOptions.Cipher, " is not supported in sing-box")
	}

	serverPort, err := strconv.ParseUint(p.clashOptions.ServerPort.Value, 10, 16)
	if err != nil {
		return nil, E.Cause(err, "fail to parse port")
	}

	opt := &option.Outbound{
		Tag:  p.Tag(),
		Type: C.TypeShadowsocks,
		ShadowsocksOptions: option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.clashOptions.Server,
				ServerPort: uint16(serverPort),
			},
			Method:   p.clashOptions.Cipher,
			Password: p.clashOptions.Password,
			//
			DialerOptions: p.dialerOptions,
		},
	}

	// plugin
	switch p.clashOptions.Plugin {
	case "":
	case "obfs":
		opts := simpleObfsOption{}
		decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
		err := decoder.Decode(p.clashOptions.PluginOpts, &opts)
		if err != nil {
			return nil, E.Cause(err, "decode obfs plugin options")
		}
		args := make(map[string][]string)
		if opts.Host != "" {
			args["obfs-host"] = []string{opts.Host}
		}
		if opts.Mode != "" {
			args["obfs"] = []string{opts.Mode}
		}
		pluginOptsStr := encodeSmethodArgs(args)
		opt.ShadowsocksOptions.Plugin = "obfs-local"
		opt.ShadowsocksOptions.PluginOptions = pluginOptsStr
	case "v2ray-plugin":
		return nil, E.New("shadowsocks plugin: ", p.clashOptions.Plugin, " is not supported in sing-box (parse from clash)")
	default:
		return nil, E.New("shadowsocks plugin: ", p.clashOptions.Plugin, " is not supported in sing-box")
	}

	if p.clashOptions.UDP != nil && !*p.clashOptions.UDP {
		opt.ShadowsocksOptions.Network = N.NetworkTCP
	}

	if p.clashOptions.UDPOverTCP {
		opt.ShadowsocksOptions.UDPOverTCPOptions = &option.UDPOverTCPOptions{
			Enabled: true,
			Version: p.clashOptions.UDPOverTCPVersion,
		}
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

func (p *ProxyShadowsocks) checkMethod() bool {
	switch p.clashOptions.Cipher {
	case "aes-128-gcm":
	case "aes-192-gcm":
	case "aes-256-gcm":
	case "aes-128-cfb":
	case "aes-192-cfb":
	case "aes-256-cfb":
	case "aes-128-ctr":
	case "aes-192-ctr":
	case "aes-256-ctr":
	case "rc4-md5":
	case "chacha20-ietf":
	case "xchacha20":
	case "chacha20-ietf-poly1305":
	case "xchacha20-ietf-poly1305":
	case "2022-blake3-aes-128-gcm":
	case "2022-blake3-aes-256-gcm":
	case "2022-blake3-chacha20-poly1305":
	default:
		return false
	}
	return true
}

type simpleObfsOption struct {
	Mode string `obfs:"mode,omitempty"`
	Host string `obfs:"host,omitempty"`
}

func backslashEscape(s string, set []byte) string {
	var buf bytes.Buffer
	for _, b := range []byte(s) {
		if b == '\\' || bytes.IndexByte(set, b) != -1 {
			buf.WriteByte('\\')
		}
		buf.WriteByte(b)
	}
	return buf.String()
}

func encodeSmethodArgs(args map[string][]string) string {
	if args == nil {
		return ""
	}

	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	escape := func(s string) string {
		return backslashEscape(s, []byte{'=', ','})
	}

	var pairs []string
	for _, key := range keys {
		for _, value := range args[key] {
			pairs = append(pairs, escape(key)+"="+escape(value))
		}
	}

	return strings.Join(pairs, ";")
}
