package goauth

// The global config variable holds the configuration for the application.
var config = new(Config)

// Config represents the configuration structure for the Socious Auth.
type Config struct {
	Secret string `json:"host" mapstructure:"host"`
}

// Setup initializes the Socious Auth SDK with the provided configuration.
func Setup(cfg Config) error {
	// Set the global configuration to the provided config.
	config = &cfg
	return nil // Return nil to indicate successful setup.
}
