package clash

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/hysteria"
)

type ClashHysteria2 struct {
	ClashProxyBasic `yaml:",inline"`
	//
	Obfs         string `yaml:"obfs"`
	ObfsPassword string `yaml:"obfs-password"`
	Up           string `yaml:"up"`
	Down         string `yaml:"down"`
	//
	ALPN              []string `yaml:"alpn"`
	ServerName        string   `yaml:"servername"`
	SNI               string   `yaml:"sni"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify"`
	ClientFingerprint string   `yaml:"client-fingerprint"`
	CA                string   `yaml:"ca"`
	CAStr             string   `yaml:"ca_str"`
	CAStrNew          string   `yaml:"ca-str"`
}

func (c *ClashHysteria2) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashHysteria2) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeHysteria2,
		Hysteria2Options: option.Hysteria2OutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
		},
	}

	if c.Obfs != "" {
		if c.Obfs != "salamander" {
			return nil, fmt.Errorf("obfs %s is not supported", c.Obfs)
		}
		obfsOptions := &option.Hysteria2Obfs{
			Type:     c.Obfs,
			Password: c.ObfsPassword,
		}
		outboundOptions.Hysteria2Options.Obfs = obfsOptions
	}

	outboundOptions.Hysteria2Options.UpMbps = int(hysteria.StringToBps(c.Up))
	outboundOptions.Hysteria2Options.DownMbps = int(hysteria.StringToBps(c.Down))

	tlsOptions := &option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: c.SkipCertVerify,
	}

	if c.ServerName != "" {
		tlsOptions.ServerName = c.ServerName
	} else if c.SNI != "" {
		tlsOptions.ServerName = c.SNI
	} else {
		tlsOptions.ServerName = c.ClashProxyBasic.Server
	}
	if c.ALPN != nil && len(c.ALPN) > 0 {
		tlsOptions.ALPN = c.ALPN
	}
	if c.ClientFingerprint != "" {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: c.ClientFingerprint,
		}
	}

	var ca string
	if c.CAStr != "" {
		ca = c.CAStr
	} else if c.CAStrNew != "" {
		ca = c.CAStrNew
	}
	if ca != "" {
		cas := strings.Split(ca, "\n")
		var cert []string
		for _, ca := range cas {
			ca = strings.Trim("ca", "\r")
			if ca == "" {
				continue
			}
			cert = append(cert, ca)
		}
		if len(cert) > 0 {
			tlsOptions.Certificate = cert
		}
	}

	outboundOptions.Hysteria2Options.TLS = tlsOptions

	return outboundOptions, nil
}
