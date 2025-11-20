// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws_sts

import (
	"context"
	"crypto/x509"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/identity"
)

type principal struct {
	// Subject ('sub') from ID token
	subject string

	// Issuer ('iss') from ID token
	issuer string

	// URI to be set in certificate. URI is of the form
	// https://<account-specific-issuer>.sts.global.api.aws
	uri string

	// AWS Account ID
	account string
}

func PrincipalFromIDToken(_ context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		STSClaims struct {
			AWSAccount string `json:"aws_account"`
		} `json:"https://sts.amazonaws.com/"`
	}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	return principal{
		subject: token.Subject,
		issuer:  token.Issuer,
		uri:     token.Subject,
		account: claims.STSClaims.AWSAccount,
	}, nil
}

func (p principal) Name(context.Context) string {
	return p.subject
}

func (p principal) Embed(_ context.Context, cert *x509.Certificate) error {
	parsed, err := url.Parse(p.uri)
	if err != nil {
		return err
	}
	cert.URIs = []*url.URL{parsed}

	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer:                          p.issuer,
		SourceRepositoryOwnerIdentifier: p.account,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
