package proxyprovider

import (
	"encoding/json"
	"os"
	"time"

	"github.com/sagernet/sing-box/option"
)

type Cache struct {
	LastUpdate time.Time         `json:"last_update,omitempty"`
	Outbounds  []option.Outbound `json:"outbounds,omitempty"`
	ClashInfo  *ClashInfo        `json:"clash_info,omitempty"`
}

type _Cache Cache

func (c *Cache) IsNil() bool {
	if c.Outbounds == nil || len(c.Outbounds) == 0 {
		return true
	}
	return false
}

func (c *Cache) WriteToFile(path string) error {
	raw, err := json.Marshal((*_Cache)(c))
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func (c *Cache) ReadFromFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, (*_Cache)(c))
}

type ClashInfo struct {
	Download uint64    `json:"download,omitempty"`
	Upload   uint64    `json:"upload,omitempty"`
	Total    uint64    `json:"total,omitempty"`
	Expire   time.Time `json:"expire,omitempty"`
}

type Group struct {
	Tag             string
	Type            string
	SelectorOptions option.SelectorOutboundOptions
	URLTestOptions  option.URLTestOutboundOptions
	JSTestOptions   option.JSTestOutboundOptions
	Filter          *Filter
}
