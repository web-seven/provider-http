/*
Copyright 2023 The Crossplane Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
)

// IdentityType used to obtain a bearer token for outgoing requests.
// +kubebuilder:validation:Enum=GoogleApplicationCredentials
type IdentityType string

// Supported identity types.
const (
	// IdentityTypeGoogleApplicationCredentials authenticates using Google
	// Application Credentials, exchanging them for an OAuth2 access token.
	IdentityTypeGoogleApplicationCredentials = "GoogleApplicationCredentials"
)

// IdentityCredentials required to obtain a token.
type IdentityCredentials struct {
	// Source of the identity credentials. Use InjectedIdentity to resolve
	// credentials from the provider pod's environment, for example through
	// Workload Identity on GKE.
	// +kubebuilder:validation:Enum=Secret;InjectedIdentity;Environment;Filesystem
	Source xpv2.CredentialsSource `json:"source"`

	xpv2.CommonCredentialSelectors `json:",inline"`
}

// Identity used to authenticate outgoing requests.
type Identity struct {
	// Type of identity.
	Type IdentityType `json:"type"`

	IdentityCredentials `json:",inline"`

	// Scopes requested for the access token. Defaults to
	// https://www.googleapis.com/auth/cloud-platform for
	// GoogleApplicationCredentials.
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}
