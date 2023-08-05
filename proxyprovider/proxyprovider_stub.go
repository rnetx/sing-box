//go:build !with_proxyprovider

package proxyprovider

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type ProxyProvider struct{}

func NewProxyProvider(ctx context.Context, router adapter.Router, logFactory log.Factory, options option.ProxyProviderOptions) (*ProxyProvider, error) {
	return nil, E.New(`ProxyProvider is not included in this build, rebuild with -tags with_proxyprovider`)
}

func (p *ProxyProvider) Tag() string {
	return ""
}

func (p *ProxyProvider) SubScribeAndParse() error {
	return E.New(`ProxyProvider is not included in this build, rebuild with -tags with_proxyprovider`)
}

func (p *ProxyProvider) GetOutbounds() ([]adapter.Outbound, error) {
	return nil, E.New(`ProxyProvider is not included in this build, rebuild with -tags with_proxyprovider`)
}

func (p *ProxyProvider) GetUpdateTime() time.Time {
	return time.Time{}
}

func (p *ProxyProvider) GetSubscribeInfo() adapter.SubScribeInfo {
	return nil
}

func (p *ProxyProvider) ForceSubScribeToCache() error {
	return E.New(`ProxyProvider is not included in this build, rebuild with -tags with_proxyprovider`)
}

func (p *ProxyProvider) GetOutboundOptions() ([]option.Outbound, error) {
	return nil, E.New(`ProxyProvider is not included in this build, rebuild with -tags with_proxyprovider`)
}
