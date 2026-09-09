package authstack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type IdentifierType string

const (
	IdentifierEmail    IdentifierType = "email"
	IdentifierUsername IdentifierType = "username"
	IdentifierPhone    IdentifierType = "phone"
)

type SessionManager interface {
	CreateSession(ctx context.Context, p Principal) error
	GetSession(ctx context.Context, sessionID string) (*Principal, error)
	RevokeSession(ctx context.Context, sessionID string) error
}

type PrincipalType string

const (
	PrincipalUser    PrincipalType = "user"
	PrincipalService PrincipalType = "service"
)

type ProviderType string

const (
	ProviderPassword    ProviderType = "password"
	ProviderOIDC        ProviderType = "oidc"
	ProviderAPIKey      ProviderType = "apikey"
	ProviderStaticToken ProviderType = "static_token"
)

type Principal struct {
	ID       string
	Type     PrincipalType
	OwnerID  *string
	Claims   map[string]any // TODO: Claims or Metadata?
	Provider ProviderType
}

type ProviderOIDCConfig struct {
	Name          string
	ClientID      string
	ClientSecret  string
	AuthEndpoint  string
	TokenEndpoint string
	RedirectURL   string
	Scopes        []string
	URLOptions    map[string]string
}

type OIDCProvider interface {
	Name() string
	BuildAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*Principal, error)
}

type StandardOIDCProvider struct {
	cfg ProviderOIDCConfig

	buildAuthURLFn   func(state string) (string, error)
	exchangeCodeFn   func(ctx context.Context, code string) (*Principal, error)
	extractProfileFn func(ctx context.Context, claims map[string]any) (*Principal, error)
}

func NewOIDCProvider(cfg ProviderOIDCConfig) (*StandardOIDCProvider, error) {
	if cfg.Name == "" {
		return nil, errors.New("authstack: provider name is required")
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	return &StandardOIDCProvider{
		cfg: cfg,
	}, nil
}

func (p *StandardOIDCProvider) Name() string {
	return p.cfg.Name
}

func (p *StandardOIDCProvider) SetBuildAuthURLHook(fn func(state string) (string, error)) {
	if fn != nil {
		p.buildAuthURLFn = fn
	}
}

func (p *StandardOIDCProvider) standardbuildAuthURL(state string) (string, error) {
	u, err := url.Parse(p.cfg.AuthEndpoint)
	if err != nil {
		return "", fmt.Errorf("authstack: invalid auth endpoint URL %q: %w", p.cfg.AuthEndpoint, err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", state)

	for k, v := range p.cfg.URLOptions {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func (p *StandardOIDCProvider) BuildAuthURL(state string) (string, error) {
	if p.buildAuthURLFn != nil {
		return p.buildAuthURLFn(state)
	}
	return p.standardbuildAuthURL(state)
}

func (p *StandardOIDCProvider) SetExtractProfileHook(fn func(ctx context.Context, claims map[string]any) (*Principal, error)) {
	if fn != nil {
		p.extractProfileFn = fn
	}
}

func (p *StandardOIDCProvider) standardExtractProfile(ctx context.Context, claims map[string]any) (*Principal, error) {
	_ = ctx

	rawSub, ok := claims["sub"]
	if !ok {
		return nil, errors.New("authstack: missing required 'sub' claim in OIDC profile")
	}

	sub, ok := rawSub.(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("authstack: invalid or non-string 'sub' claim type: %T", rawSub)
	}

	return &Principal{
		ID:       sub,
		Type:     PrincipalUser,
		Provider: ProviderOIDC,
		Claims:   claims,
	}, nil
}

func (p *StandardOIDCProvider) ExtractProfile(ctx context.Context, claims map[string]any) (*Principal, error) {
	if p.extractProfileFn != nil {
		return p.extractProfileFn(ctx, claims)
	}
	return p.standardExtractProfile(ctx, claims)
}

func (p *StandardOIDCProvider) SetExchangeCodeHook(fn func(ctx context.Context, code string) (*Principal, error)) {
	if fn != nil {
		p.exchangeCodeFn = fn
	}
}

func (p *StandardOIDCProvider) standardExchangeCode(ctx context.Context, code string) (*Principal, error) {
	if code == "" {
		return nil, errors.New("authstack: empty authorization code")
	}

	rawClaims := map[string]any{}

	return p.ExtractProfile(ctx, rawClaims)
}

func (p *StandardOIDCProvider) ExchangeCode(ctx context.Context, code string) (*Principal, error) {
	if p.exchangeCodeFn != nil {
		return p.exchangeCodeFn(ctx, code)
	}
	return p.standardExchangeCode(ctx, code)
}

type OIDCStateData struct {
	State         string    `json:"state"`
	CorrelationID string    `json:"correlation_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type OIDCStateStore interface {
	SaveState(ctx context.Context, state string, data OIDCStateData) error
	GetAndClearState(ctx context.Context, state string) (*OIDCStateData, error)
}

type OIDCConfig struct {
	oidcStateStore OIDCStateStore
	oidcProviders  map[string]OIDCProvider
}

type StaticTokenAuthenticator interface {
	AuthenticateStaticToken(ctx context.Context, token string) (*Principal, error)
}

type StaticTokenConfig struct {
	Header                   string
	FormatValidator          func(token string) error
	staticTokenAuthenticator StaticTokenAuthenticator
}

type config struct {
	sessionManager SessionManager
	password       PasswordConfig
	oidc           OIDCConfig
	staticToken    StaticTokenConfig
	stateGenFn     func() (string, error)
}

type AuthStack struct {
	cfg config
}

type Option func(*config) error

func New(opts ...Option) (*AuthStack, error) {
	var cfg config

	cfg.stateGenFn = defaultStateGenerator

	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, fmt.Errorf("authstack: option failed: %w", err)
		}
	}

	return &AuthStack{cfg: cfg}, nil
}

func WithSessionManager(sm SessionManager) Option {
	return func(c *config) error {
		c.sessionManager = sm
		return nil
	}
}

func WithProviderPassword(cfg PasswordConfig) Option {
	return func(c *config) error {
		c.password = cfg
		return nil
	}
}

func WithProviderOIDC(cfg OIDCConfig) Option {
	return func(c *config) error {
		c.oidc = cfg
		return nil
	}
}

func WithProviderStaticToken(cfg StaticTokenConfig) Option {
	return func(c *config) error {
		c.staticToken = cfg
		return nil
	}
}

func WithStateGenerator(fn func() (string, error)) Option {
	return func(c *config) error {
		if fn == nil {
			return errors.New("authstack: state generator function cannot be nil")
		}
		c.stateGenFn = fn
		return nil
	}
}

func defaultStateGenerator() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authstack: failed to generate secure state: %w", err)
	}
	return hex.EncodeToString(b), nil
}
