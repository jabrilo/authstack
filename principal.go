package authstack

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
	Claims   map[string]any
	Provider ProviderType
}
