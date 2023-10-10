package option

type RuleProvider struct {
	Tag            string        `json:"tag"`
	Url            string        `json:"url"`
	Behavior       string        `json:"behavior,omitempty"`
	Format         string        `json:"format,omitempty"`
	CacheFile      string        `json:"cache_file,omitempty"`
	UseH3          bool          `json:"use_h3,omitempty"`
	UpdateInterval Duration      `json:"update_interval,omitempty"`
	RequestTimeout Duration      `json:"request_timeout,omitempty"`
	DNS            string        `json:"dns,omitempty"`
	RequestDialer  DialerOptions `json:"request_dialer,omitempty"`
	RunningDetour  string        `json:"running_detour,omitempty"`
}
