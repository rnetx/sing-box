package provider

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type Action interface {
	Unmarshal(m map[string]any) error
	Apply(p *PreProcessSet) error
}

type actionFunc func() Action

var actionMap map[string]actionFunc

func init() {
	actionMap = make(map[string]actionFunc)
}

func RegisterAction(_type string, f actionFunc) {
	actionMap[_type] = f
}

func NewAction(options option.ProviderOutboundActionOptions) (Action, error) {
	f, ok := actionMap[options.Type]
	if !ok {
		return nil, E.New("unknown action type: ", options.Type)
	}
	ac := f()
	if ac == nil {
		return nil, E.New("unknown action type: ", options.Type)
	}
	err := ac.Unmarshal(options.RawMessage)
	if err != nil {
		return nil, err
	}
	return ac, nil
}
