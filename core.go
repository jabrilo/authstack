package authstack

type IdentifierType string

const (
	EmailIdentifier    IdentifierType = "email"
	UsernameIdentifier IdentifierType = "username"
	PhoneIdentifier    IdentifierType = "phone"
)

type IdentityCustomizer func(id string) bool

type PasswordConfig struct {
	IdentityCustomizers map[IdentifierType]IdentityCustomizer
	AllowedIdentifiers  []IdentifierType
}

type OIDCConfig struct{}

type SessionManager interface {
	Load() error
	Commit() error
}

type PasswordStore interface {
	Verify() error
}

type OIDCStore interface {
	Callback() error
}

type Config struct {
	SessionManager SessionManager
	PasswordStore  PasswordStore
	PasswordConfig *PasswordConfig
	OIDCStore      OIDCStore
	OIDCProviders  map[string]*OIDCConfig
}

type AuthStack struct{ config Config }

type Option func(*Config)

func New(opts ...Option) (*AuthStack, error) {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &AuthStack{config: cfg}, nil
}

func WithPassword(idt ...IdentifierType) Option {
	return func(c *Config) {
		c.PasswordConfig = &PasswordConfig{AllowedIdentifiers: idt}
	}
}

func WithOIDCProvider(s OIDCStore) Option {
	return func(c *Config) {
		c.OIDCStore = s
	}
}
