package raw

import (
	"encoding/base64"
	"fmt"
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
	for i, r := range rawList {
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
		switch head {
		case "http", "https":
			peer = &HTTP{}
		case "socks", "socks4", "socks4a", "socks5", "socks5h":
			peer = &Socks{}
		case "hysteria":
			peer = &Hysteria{}
		case "hy2", "hysteria2":
			peer = &Hysteria2{}
		case "ss":
			peer = &Shadowsocks{}
		case "trojan":
			peer = &Trojan{}
		case "vmess":
			peer = &VMess{}
		case "vless":
			peer = &VLESS{}
		case "tuic":
			peer = &Tuic{}
		default:
			continue
		}
		err = peer.ParseLink(head + "://" + ss[1])
		if err != nil {
			return nil, fmt.Errorf("parse proxy[%d] failed: %s", i+1, err)
		}
		peerList = append(peerList, *peer.Options())
	}
	if len(peerList) == 0 {
		return nil, fmt.Errorf("no outbounds found in raw link")
	}
	return peerList, nil
}
