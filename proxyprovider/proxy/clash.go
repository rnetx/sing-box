//go:build with_proxyprovider

package proxy

import (
	E "github.com/sagernet/sing/common/exceptions"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Proxies []ProxyClashOptions `yaml:"proxies"`
}

const (
	ClashTypeHTTP         = "http"
	ClashTypeSocks5       = "socks5"
	ClashTypeShadowsocks  = "ss"
	ClashTypeShadowsocksR = "ssr"
	ClashTypeVMess        = "vmess"
	ClashTypeTrojan       = "trojan"
	ClashTypeVLESS        = "vless"
	ClashTypeHysteria     = "hysteria"
	ClashTypeTUIC         = "tuic"
)

type proxyClashDefault struct {
	Name       string    `yaml:"name"`
	Type       string    `yaml:"type"`
	Server     string    `yaml:"server"`
	ServerPort yaml.Node `yaml:"port"`
	//
	IPVersion string `yaml:"ip-version,omitempty"`
}

type ProxyClashOptions struct {
	Type                string                 `yaml:"type"`
	HTTPOptions         proxyClashHTTP         `yaml:"-"`
	SocksOptions        proxyClashSocks        `yaml:"-"`
	ShadowsocksOptions  proxyClashShadowsocks  `yaml:"-"`
	ShadowsocksROptions proxyClashShadowsocksR `yaml:"-"`
	VMessOptions        proxyClashVMess        `yaml:"-"`
	TrojanOptions       proxyClashTrojan       `yaml:"-"`
	VLESSOptions        proxyClashVLESS        `yaml:"-"`
	HysteriaOptions     proxyClashHysteria     `yaml:"-"`
	TUICOptions         proxyClashTUIC         `yaml:"-"`
}

type _proxyClashOptions ProxyClashOptions

func (p *ProxyClashOptions) UnmarshalYAML(unmarshal func(any) error) error {
	var raw _proxyClashOptions
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*p = ProxyClashOptions{
		Type: raw.Type,
	}
	switch raw.Type {
	case ClashTypeHTTP:
		return unmarshal(&p.HTTPOptions)
	case ClashTypeSocks5:
		return unmarshal(&p.SocksOptions)
	case ClashTypeShadowsocks:
		return unmarshal(&p.ShadowsocksOptions)
	case ClashTypeShadowsocksR:
		return unmarshal(&p.ShadowsocksROptions)
	case ClashTypeVMess:
		return unmarshal(&p.VMessOptions)
	case ClashTypeTrojan:
		return unmarshal(&p.TrojanOptions)
	case ClashTypeVLESS:
		return unmarshal(&p.VLESSOptions)
	case ClashTypeHysteria:
		return unmarshal(&p.HysteriaOptions)
	case ClashTypeTUIC:
		return unmarshal(&p.TUICOptions)
	default:
		// return E.New("unsupported clash proxy type: ", raw.Type)
		return nil
	}
}

func (p *ProxyClashOptions) ToProxy() (Proxy, error) {
	var opt Proxy
	switch p.Type {
	case ClashTypeHTTP:
		opt = &ProxyHTTP{}
		opt.SetClashOptions(p.HTTPOptions)
	case ClashTypeSocks5:
		opt = &ProxySocks{}
		opt.SetClashOptions(p.SocksOptions)
	case ClashTypeShadowsocks:
		opt = &ProxyShadowsocks{}
		opt.SetClashOptions(p.ShadowsocksOptions)
	case ClashTypeShadowsocksR:
		opt = &ProxyShadowsocksR{}
		opt.SetClashOptions(p.ShadowsocksROptions)
	case ClashTypeVMess:
		opt = &ProxyVMess{}
		opt.SetClashOptions(p.VMessOptions)
	case ClashTypeTrojan:
		opt = &ProxyTrojan{}
		opt.SetClashOptions(p.TrojanOptions)
	case ClashTypeVLESS:
		opt = &ProxyVLESS{}
		opt.SetClashOptions(p.VLESSOptions)
	case ClashTypeHysteria:
		opt = &ProxyHysteria{}
		opt.SetClashOptions(p.HysteriaOptions)
	case ClashTypeTUIC:
		opt = &ProxyTUIC{}
		opt.SetClashOptions(p.TUICOptions)
	default:
		return nil, E.New("unsupported clash proxy type: ", p.Type)
	}
	opt.Tag()
	return opt, nil
}
