package singbox

import (
	"github.com/sagernet/sing-box/common/json"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type OutboundConfig struct {
	Outbounds []option.Outbound `yaml:"outbounds"`
}

func ParseSingboxConfig(raw []byte) ([]option.Outbound, error) {
	var outboundConfig OutboundConfig
	err := json.Unmarshal(raw, &outboundConfig)
	if err != nil {
		return nil, err
	}
	var options []option.Outbound
	for _, outboundOptions := range outboundConfig.Outbounds {
		switch outboundOptions.Type {
		// TODO: Remove Direct ???
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeURLTest, C.TypeSelector:
			continue
		default:
			// TODO: Remove Detour ???
			removeDetour(&outboundOptions)
			options = append(options, outboundOptions)
		}
	}
	return options, nil
}

func removeDetour(outbound *option.Outbound) {
	switch outbound.Type {
	case C.TypeDirect:
		outbound.DirectOptions.DialerOptions.Detour = ""
	case C.TypeHTTP:
		outbound.HTTPOptions.DialerOptions.Detour = ""
	case C.TypeShadowsocks:
		outbound.ShadowsocksOptions.DialerOptions.Detour = ""
	case C.TypeVMess:
		outbound.VMessOptions.DialerOptions.Detour = ""
	case C.TypeTrojan:
		outbound.TrojanOptions.DialerOptions.Detour = ""
	case C.TypeWireGuard:
		outbound.WireGuardOptions.DialerOptions.Detour = ""
	case C.TypeHysteria:
		outbound.HysteriaOptions.DialerOptions.Detour = ""
	case C.TypeTor:
		outbound.TorOptions.DialerOptions.Detour = ""
	case C.TypeSSH:
		outbound.SSHOptions.DialerOptions.Detour = ""
	case C.TypeShadowTLS:
		outbound.ShadowTLSOptions.DialerOptions.Detour = ""
	case C.TypeShadowsocksR:
		outbound.ShadowsocksROptions.DialerOptions.Detour = ""
	case C.TypeVLESS:
		outbound.VLESSOptions.DialerOptions.Detour = ""
	case C.TypeTUIC:
		outbound.TUICOptions.DialerOptions.Detour = ""
	case C.TypeHysteria2:
		outbound.Hysteria2Options.DialerOptions.Detour = ""
	case C.TypeRandomAddr:
		outbound.RandomAddrOptions.DialerOptions.Detour = ""
	default:
	}
}
