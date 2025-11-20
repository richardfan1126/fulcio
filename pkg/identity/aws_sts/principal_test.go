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
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
)

func TestPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Claims            map[string]interface{}
		ExpectedPrincipal principal
		WantErr           bool
	}{
		`Valid token authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"aud": []string{"sigstore"},
				"iss": "https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws",
				"sub": "arn:aws:iam::123456789012:role/DataProcessingRole",
				"https://sts.amazonaws.com/": map[string]interface{}{
					"aws_account": "123456789012",
				},
			},
			ExpectedPrincipal: principal{
				issuer:  "https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws",
				subject: "arn:aws:iam::123456789012:role/DataProcessingRole",
				uri:     "arn:aws:iam::123456789012:role/DataProcessingRole",
				account: "123456789012",
			},
			WantErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := &oidc.IDToken{
				Issuer:  test.Claims["iss"].(string),
				Subject: test.Claims["sub"].(string),
			}
			claims, err := json.Marshal(test.Claims)
			if err != nil {
				t.Fatal(err)
			}
			withClaims(token, claims)

			untyped, err := PrincipalFromIDToken(context.TODO(), token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Fatal("expected error but got none")
			}

			gotPrincipal, ok := untyped.(principal)
			if !ok {
				t.Errorf("Got wrong principal type %v", untyped)
			}
			if gotPrincipal != test.ExpectedPrincipal {
				t.Errorf("got %v principal and expected %v", gotPrincipal, test.ExpectedPrincipal)
			}
		})
	}
}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func withClaims(token *oidc.IDToken, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(token))
	member := val.FieldByName("claims")
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}

func TestName(t *testing.T) {
	tests := map[string]struct {
		Claims       map[string]interface{}
		ExpectedName string
	}{
		`Valid token authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"aud": []string{"sigstore"},
				"iss": "https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws",
				"sub": "arn:aws:iam::123456789012:role/DataProcessingRole",
			},
			ExpectedName: "arn:aws:iam::123456789012:role/DataProcessingRole",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := &oidc.IDToken{
				Issuer:  test.Claims["iss"].(string),
				Subject: test.Claims["sub"].(string),
			}
			claims, err := json.Marshal(test.Claims)
			if err != nil {
				t.Fatal(err)
			}
			withClaims(token, claims)

			got, err := PrincipalFromIDToken(context.TODO(), token)
			if err != nil {
				t.Fatal("didn't expect error", err)
			}

			if got.Name(context.TODO()) != test.ExpectedName {
				t.Errorf("got name %v and expected %v", got.Name(context.TODO()), test.ExpectedName)
			}
		})
	}
}

func TestEmbed(t *testing.T) {
	tests := map[string]struct {
		Principal principal
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`Good STS web token`: {
			Principal: principal{
				issuer:  `https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws`,
				uri:     "arn:aws:iam::123456789012:role/DataProcessingRole",
				account: "123456789012",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws`: factIssuerIs(`https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws`),
				`Account is 123456789012`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}, `123456789012`),
				`SAN is arn:aws:iam::123456789012:role/DataProcessingRole`: func(cert x509.Certificate) error {
					WantURI, err := url.Parse("arn:aws:iam::123456789012:role/DataProcessingRole")
					if err != nil {
						return err
					}
					if len(cert.URIs) != 1 {
						return errors.New("no URI SAN set")
					}
					if diff := cmp.Diff(cert.URIs[0], WantURI); diff != "" {
						return errors.New(diff)
					}
					return nil
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var cert x509.Certificate
			err := test.Principal.Embed(context.TODO(), &cert)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				}
				return
			} else if test.WantErr {
				t.Error("expected error")
			}
			for factName, fact := range test.WantFacts {
				t.Run(factName, func(t *testing.T) {
					if err := fact(cert); err != nil {
						t.Error(err)
					}
				})
			}
		})
	}

}

func factIssuerIs(issuer string) func(x509.Certificate) error {
	return factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, issuer)
}

func factExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
	return func(cert x509.Certificate) error {
		for _, ext := range cert.ExtraExtensions {
			if ext.Id.Equal(oid) {
				var strVal string
				_, _ = asn1.Unmarshal(ext.Value, &strVal)
				if value != strVal {
					return fmt.Errorf("expected oid %v to be %s, but got %s", oid, value, strVal)
				}
				return nil
			}
		}
		return errors.New("extension not set")
	}
}
