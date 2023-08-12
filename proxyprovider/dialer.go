//go:build with_proxyprovider

package proxyprovider

import (
	D "github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (p *ProxyProvider) initRequestDialer() error {
	requestDialerOptions := common.PtrValueOrDefault(p.options.RequestDialerOptions)
	dialerOptions := option.DialerOptions{
		BindInterface:      requestDialerOptions.BindInterface,
		Inet4BindAddress:   requestDialerOptions.Inet4BindAddress,
		Inet6BindAddress:   requestDialerOptions.Inet6BindAddress,
		ProtectPath:        requestDialerOptions.ProtectPath,
		RoutingMark:        requestDialerOptions.RoutingMark,
		ReuseAddr:          requestDialerOptions.ReuseAddr,
		ConnectTimeout:     requestDialerOptions.ConnectTimeout,
		TCPFastOpen:        requestDialerOptions.TCPFastOpen,
		UDPFragment:        requestDialerOptions.UDPFragment,
		UDPFragmentDefault: requestDialerOptions.UDPFragmentDefault,
	}
	dialer, err := D.NewSimple(dialerOptions)
	if err != nil {
		return err
	}
	p.dialer = dialer
	return nil
}
