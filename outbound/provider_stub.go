//go:build !with_provider

package outbound

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewProvider(ctx context.Context, router adapter.Router, logFactory log.Factory, logger log.ContextLogger, tag string, options option.ProviderOutboundOptions) (adapter.Outbound, error) {
	return nil, E.New(`Provider is not included in this build, rebuild with -tags with_provider`)
}
