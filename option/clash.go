package option

type ClashAPIOptions struct {
	ExternalController       string `json:"external_controller,omitempty"`
	ExternalUI               string `json:"external_ui,omitempty"`
	ExternalUIBuildIn        bool   `json:"external_ui_build_in,omitempty"`
	ExternalUIDownloadURL    string `json:"external_ui_download_url,omitempty"`
	ExternalUIDownloadDetour string `json:"external_ui_download_detour,omitempty"`
	Secret                   string `json:"secret,omitempty"`
	DefaultMode              string `json:"default_mode,omitempty"`
	StoreSelected            bool   `json:"store_selected,omitempty"`
	StoreFakeIP              bool   `json:"store_fakeip,omitempty"`
	CacheFile                string `json:"cache_file,omitempty"`
	CacheID                  string `json:"cache_id,omitempty"`
}

type SelectorOutboundOptions struct {
	Outbounds []string `json:"outbounds"`
	Default   string   `json:"default,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds []string               `json:"outbounds"`
	URL       string                 `json:"url,omitempty"`
	Interval  Duration               `json:"interval,omitempty"`
	Tolerance uint16                 `json:"tolerance,omitempty"`
	Fallback  URLTestFallbackOptions `json:"fallback,omitempty"`
}

type URLTestFallbackOptions struct {
	Enabled  bool   `json:"enabled,omitempty"`
	MaxDelay uint16 `json:"max_delay,omitempty"`
}
