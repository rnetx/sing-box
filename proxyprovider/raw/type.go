package raw

import (
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// From Homeproxy

type RawInterface interface {
	Tag() string
	ParseLink(link string) error
	Options() *option.Outbound
}

func ParseRawConfig(raw []byte) ([]option.Outbound, error) {
	rawStr := string(raw)
	rawStr = strings.TrimSpace(rawStr)
	_raw, err := base64.URLEncoding.DecodeString(rawStr)
	if err == nil {
		rawStr = string(_raw)
	}
	rawList := strings.Split(rawStr, "\n")
	var peerList []option.Outbound
	for _, r := range rawList {
		rs := string(r)
		rs = strings.TrimSpace(rs)
		if rs == "" {
			continue
		}
		ss := strings.SplitN(rs, "://", 2)
		if len(ss) != 2 {
			continue
		}
		head := ss[0]
		var peer RawInterface
		switch {
		case head == "http" || head == "https":
			peer = &HTTP{}
		case head == "socks" || head == "socks4" || head == "socks4a" || head == "socks5" || head == "socks5h":
			peer = &Socks{}
		case head == "hysteria":
			peer = &Hysteria{}
		case head == "hy2" || head == "hysteria2":
			peer = &Hysteria2{}
		case head == "ss":
			peer = &Shadowsocks{}
		case head == "trojan":
			peer = &Trojan{}
		case head == "vmess":
			peer = &VMess{}
		case head == "vless":
			peer = &VLESS{}
		case head == "tuic":
			peer = &Tuic{}
		default:
			continue
		}
		err = peer.ParseLink(head + "://" + ss[1])
		if err != nil {
			return nil, err
		}
		peerList = append(peerList, *peer.Options())
	}
	return peerList, nil
}
