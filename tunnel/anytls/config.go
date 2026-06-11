package anytls

// ServerConfig holds the configuration for the anytls server.
type ServerConfig struct {
	Listen        string `json:"listen"`
	PaddingScheme string `json:"padding_scheme,omitempty"`
}
