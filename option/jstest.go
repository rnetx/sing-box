package option

type JSTestOutboundOptions struct {
	Outbounds                 []string `json:"outbounds"`
	JSPath                    string   `json:"js_path"`
	JSBase64                  string   `json:"js_base64"`
	Interval                  Duration `json:"interval,omitempty"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}
