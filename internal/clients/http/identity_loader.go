package http

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/crossplane-contrib/provider-http/apis/common"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	kube "sigs.k8s.io/controller-runtime/pkg/client"
)

// DefaultGoogleScopes are requested when an identity configures no scopes.
var DefaultGoogleScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// LoadIdentityTokenSource builds an OAuth2 token source from the identity
// configured on a ProviderConfig. It returns a nil token source when no
// identity is configured, in which case requests are sent unauthenticated
// unless they carry their own Authorization header.
func LoadIdentityTokenSource(ctx context.Context, kubeClient kube.Client, identity *common.Identity) (oauth2.TokenSource, error) {
	if identity == nil {
		return nil, nil
	}

	switch identity.Type {
	case common.IdentityTypeGoogleApplicationCredentials:
		return googleTokenSource(ctx, kubeClient, identity)
	default:
		return nil, fmt.Errorf("unsupported identity type %q", identity.Type)
	}
}

// googleTokenSource resolves Google Application Credentials into a token
// source. Credentials in JSON format are exchanged for access tokens; a
// non-JSON value is treated as an access token itself. When the source is
// InjectedIdentity the token is resolved from the provider pod's environment,
// which on GKE means Workload Identity.
func googleTokenSource(ctx context.Context, kubeClient kube.Client, identity *common.Identity) (oauth2.TokenSource, error) {
	scopes := identity.Scopes
	if len(scopes) == 0 {
		scopes = DefaultGoogleScopes
	}

	if identity.Source == xpv2.CredentialsSourceInjectedIdentity {
		ts, err := google.DefaultTokenSource(ctx, scopes...)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve default Google credentials: %w", err)
		}
		return oauth2.ReuseTokenSource(nil, ts), nil
	}

	credentials, err := loadIdentityCredentials(ctx, kubeClient, identity)
	if err != nil {
		return nil, err
	}

	if !isJSON(credentials) {
		token := &oauth2.Token{AccessToken: string(credentials)}
		if !token.Valid() {
			return nil, fmt.Errorf("google identity credentials are neither valid JSON nor a valid access token")
		}
		return oauth2.StaticTokenSource(token), nil
	}

	creds, err := google.CredentialsFromJSON(ctx, credentials, scopes...) //nolint:staticcheck // SA1019: credentials come from a Secret we already trust; no drop-in replacement yet
	if err != nil {
		return nil, fmt.Errorf("cannot load Google Application Credentials from JSON: %w", err)
	}

	return creds.TokenSource, nil
}

// loadIdentityCredentials reads the identity credentials from its configured
// source.
func loadIdentityCredentials(ctx context.Context, kubeClient kube.Client, identity *common.Identity) ([]byte, error) {
	if identity.Source != xpv2.CredentialsSourceSecret {
		return nil, fmt.Errorf("unsupported identity credentials source %q", identity.Source)
	}

	if identity.SecretRef == nil {
		return nil, fmt.Errorf("identity credentials source is Secret but no secretRef is set")
	}

	return loadSecretData(ctx, kubeClient, identity.SecretRef)
}

// isJSON reports whether b is valid JSON.
func isJSON(b []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(b, &js) == nil
}
