package adapter

import (
	"context"
	"time"
)

type ProviderOutbound interface {
	Outbound
	Service
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	CallUpdate()
	HealthCheck(ctx context.Context, url string) error
	ProviderInfo() ProviderInfo
}

type ProviderInfo struct {
	UpdateTime time.Time `json:"update_time,omitempty"`
	ExpireTime time.Time `json:"expire_time,omitempty"`
	Total      uint64    `json:"total,omitempty"`
	Download   uint64    `json:"download,omitempty"`
	Upload     uint64    `json:"upload,omitempty"`
}
