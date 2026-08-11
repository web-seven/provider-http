package http

import (
	"context"
	"testing"

	"github.com/crossplane-contrib/provider-http/apis/common"
	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
	"github.com/crossplane/crossplane-runtime/v2/pkg/test"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kube "sigs.k8s.io/controller-runtime/pkg/client"
)

// secretWith returns a kube client serving a single secret key.
func secretWith(name, namespace, key string, value []byte) kube.Client {
	return &test.MockClient{
		MockGet: func(ctx context.Context, k kube.ObjectKey, obj kube.Object) error {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				return errors.New("unexpected object type")
			}
			*secret = corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Data:       map[string][]byte{key: value},
			}
			return nil
		},
	}
}

func TestLoadIdentityTokenSource(t *testing.T) {
	secretRef := &xpv2.SecretKeySelector{
		SecretReference: xpv2.SecretReference{Name: "gcp-credentials", Namespace: "crossplane-system"},
		Key:             "credentials.json",
	}

	// A syntactically valid service account key. The private key is a throwaway
	// generated for this test and is not usable against Google's API.
	saKey := []byte(`{
  "type": "service_account",
  "project_id": "example",
  "private_key_id": "0",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAyE0hZ4pAsFCFdCF+\nJVMLAyLhQKHM5vLZ0eFCsyPQEmVKcbhYUZQvXCzuHrCoQfhVMJlHKzJPnrPqvxHF\nOZTPGwIDAQABAkA7VfDTQIf1nRQ4tG3nQEGZUCJZ2xLwXK4V6LqBQPWJ2Xy0aQzX\nnJRVpQKJZQ0Jg9HXqRhbxcRLZgVHnKKZAiEA8kLQ0hRpJZQKZ7Zx0hRVFQnFVQVF\nJZQKZ7Zx0hRVFQ0CIQDTQVFJZQKZ7Zx0hRVFQnFVQVFJZQKZ7Zx0hRVFQnFVQIhAK\n-----END PRIVATE KEY-----\n",
  "client_email": "example@example.iam.gserviceaccount.com",
  "client_id": "0",
  "token_uri": "https://oauth2.googleapis.com/token"
}`)

	cases := map[string]struct {
		kubeClient kube.Client
		identity   *common.Identity
		wantNil    bool
		wantErr    bool
	}{
		"NoIdentity": {
			identity: nil,
			wantNil:  true,
		},
		"UnsupportedType": {
			identity: &common.Identity{Type: "SomethingElse"},
			wantErr:  true,
		},
		"SecretSourceWithoutRef": {
			identity: &common.Identity{
				Type:                common.IdentityTypeGoogleApplicationCredentials,
				IdentityCredentials: common.IdentityCredentials{Source: xpv2.CredentialsSourceSecret},
			},
			wantErr: true,
		},
		"UnsupportedSource": {
			identity: &common.Identity{
				Type:                common.IdentityTypeGoogleApplicationCredentials,
				IdentityCredentials: common.IdentityCredentials{Source: xpv2.CredentialsSourceNone},
			},
			wantErr: true,
		},
		"AccessTokenFromSecret": {
			kubeClient: secretWith("gcp-credentials", "crossplane-system", "credentials.json", []byte("ya29.an-access-token")),
			identity: &common.Identity{
				Type: common.IdentityTypeGoogleApplicationCredentials,
				IdentityCredentials: common.IdentityCredentials{
					Source:                    xpv2.CredentialsSourceSecret,
					CommonCredentialSelectors: xpv2.CommonCredentialSelectors{SecretRef: secretRef},
				},
			},
		},
		"ServiceAccountKeyFromSecret": {
			kubeClient: secretWith("gcp-credentials", "crossplane-system", "credentials.json", saKey),
			identity: &common.Identity{
				Type: common.IdentityTypeGoogleApplicationCredentials,
				IdentityCredentials: common.IdentityCredentials{
					Source:                    xpv2.CredentialsSourceSecret,
					CommonCredentialSelectors: xpv2.CommonCredentialSelectors{SecretRef: secretRef},
				},
			},
		},
		"EmptyCredentialsRejected": {
			kubeClient: secretWith("gcp-credentials", "crossplane-system", "credentials.json", []byte("")),
			identity: &common.Identity{
				Type: common.IdentityTypeGoogleApplicationCredentials,
				IdentityCredentials: common.IdentityCredentials{
					Source:                    xpv2.CredentialsSourceSecret,
					CommonCredentialSelectors: xpv2.CommonCredentialSelectors{SecretRef: secretRef},
				},
			},
			wantErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts, err := LoadIdentityTokenSource(context.Background(), tc.kubeClient, tc.identity)

			if tc.wantErr {
				if err == nil {
					t.Fatal("LoadIdentityTokenSource(...): expected an error, got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadIdentityTokenSource(...): unexpected error: %v", err)
			}

			if tc.wantNil && ts != nil {
				t.Fatal("LoadIdentityTokenSource(...): expected a nil token source")
			}

			if !tc.wantNil && ts == nil {
				t.Fatal("LoadIdentityTokenSource(...): expected a token source, got nil")
			}
		})
	}
}
