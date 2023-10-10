package singbox

import (
	"github.com/sagernet/sing-box/common/json"
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
	return outboundConfig.Outbounds, nil
}
