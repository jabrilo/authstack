package password

type Config struct {
	Hasher                 Hasher
	IdentityResolver       IdentityResolverHook
	AllowedIdentifiers     []IdentifierType
	EnumerationGuardSecret string
}

type Option func(*Config)

func WithHasher(h Hasher) Option {
	return func(c *Config) { c.Hasher = h }
}

func WithAllowedIdentifiers(types ...IdentifierType) Option {
	return func(c *Config) { c.AllowedIdentifiers = types }
}

func WithEnumerationGuardSecret(secret string) Option {
	return func(c *Config) { c.EnumerationGuardSecret = secret }
}

func WithIdentityResolver(h IdentityResolverHook) Option {
	return func(c *Config) { c.IdentityResolver = h }
}

func NewConfig(opts ...Option) Config {
	cfg := Config{
		Hasher:                 DefaultHasher(),
		EnumerationGuardSecret: defaultEnumerationGuardSecret,
		IdentityResolver:       defaultIdentityResolver,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Hasher == nil {
		cfg.Hasher = DefaultHasher()
	}

	if cfg.EnumerationGuardSecret == "" {
		cfg.EnumerationGuardSecret = defaultEnumerationGuardSecret
	}

	if cfg.IdentityResolver == nil {
		cfg.IdentityResolver = defaultIdentityResolver
	}

	return cfg
}
