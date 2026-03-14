// Copyright 2026 The Inspektor Gadget authors
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

package gadgetservice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestHasNamespaceFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		paramValues map[string]string
		want        bool
	}{
		{
			name:        "global filter with valid namespace",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			want:        true,
		},
		{
			name:        "datasource-scoped filter with valid namespace",
			paramValues: map[string]string{operatorFilterParamKey + ".events": "pid==1,k8s.namespace==kube-system"},
			want:        true,
		},
		{
			name:        "valid namespace with uppercase and digits",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==Team-42"},
			want:        true,
		},
		{
			name:        "namespace clause absent",
			paramValues: map[string]string{operatorFilterParamKey: "pid==1,comm==nginx"},
			want:        false,
		},
		{
			name:        "namespace value contains underscore",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==my_ns"},
			want:        false,
		},
		{
			name:        "namespace value contains dot",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==my.ns"},
			want:        false,
		},
		{
			name:        "namespace value is empty",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace=="},
			want:        false,
		},
		{
			name:        "no filter key at all",
			paramValues: map[string]string{"runtime.some": "value"},
			want:        false,
		},
		{
			name:        "nil params",
			paramValues: nil,
			want:        false,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasNamespaceFilter(tc.paramValues); got != tc.want {
				t.Fatalf("hasNamespaceFilter() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHasPodnameFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		paramValues map[string]string
		want        bool
	}{
		{
			name:        "standard deployment pod with two suffixes",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.podname~nginx-7b9f5d8-abc12"},
			want:        true,
		},
		{
			name:        "two-segment pod name",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.podname~my-pod"},
			want:        true,
		},
		{
			name:        "datasource-scoped key",
			paramValues: map[string]string{operatorFilterParamKey + ".events": "k8s.podname~web-abc"},
			want:        true,
		},
		{
			name:        "combined filter alongside namespace clause",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default,k8s.podname~nginx-abc-def"},
			want:        true,
		},
		{
			name:        "podname clause absent",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			want:        false,
		},
		{
			name:        "podname has no dash separator",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.podname~nginx"},
			want:        false,
		},
		{
			name:        "podname value contains underscore",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.podname~my_pod-abc"},
			want:        false,
		},
		{
			name:        "podname value is empty",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.podname~"},
			want:        false,
		},
		{
			name:        "no filter key at all",
			paramValues: map[string]string{"runtime.some": "value"},
			want:        false,
		},
		{
			name:        "nil params",
			paramValues: nil,
			want:        false,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasPodnameFilter(tc.paramValues); got != tc.want {
				t.Fatalf("hasPodnameFilter() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateFilterParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		requireNamespace bool
		requirePodname   bool
		paramValues      map[string]string
		expectError      bool
	}{
		// Both flags off — always passes regardless of filter contents.
		{
			name:             "no requirements: nil params accepted",
			requireNamespace: false,
			requirePodname:   false,
			paramValues:      nil,
			expectError:      false,
		},
		{
			name:             "no requirements: empty params accepted",
			requireNamespace: false,
			requirePodname:   false,
			paramValues:      map[string]string{},
			expectError:      false,
		},

		// --require-namespace only.
		{
			name:             "require-namespace: valid namespace present",
			requireNamespace: true,
			requirePodname:   false,
			paramValues:      map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			expectError:      false,
		},
		{
			name:             "require-namespace: namespace missing",
			requireNamespace: true,
			requirePodname:   false,
			paramValues:      map[string]string{operatorFilterParamKey: "pid==1"},
			expectError:      true,
		},
		{
			name:             "require-namespace: podname present but namespace absent",
			requireNamespace: true,
			requirePodname:   false,
			paramValues:      map[string]string{operatorFilterParamKey: "k8s.podname~nginx-abc"},
			expectError:      true,
		},

		// --require-podname only.
		{
			name:             "require-podname: valid podname present",
			requireNamespace: false,
			requirePodname:   true,
			paramValues:      map[string]string{operatorFilterParamKey: "k8s.podname~nginx-abc-def"},
			expectError:      false,
		},
		{
			name:             "require-podname: podname missing",
			requireNamespace: false,
			requirePodname:   true,
			paramValues:      map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			expectError:      true,
		},

		// Both flags on.
		{
			name:             "both: valid namespace and podname in single key",
			requireNamespace: true,
			requirePodname:   true,
			paramValues: map[string]string{
				operatorFilterParamKey: "k8s.namespace==default,k8s.podname~nginx-abc-def",
			},
			expectError: false,
		},
		{
			name:             "both: valid across datasource-scoped key",
			requireNamespace: true,
			requirePodname:   true,
			paramValues: map[string]string{
				operatorFilterParamKey + ".events": "k8s.namespace==kube-system,k8s.podname~coredns-7b9-abc",
			},
			expectError: false,
		},
		{
			name:             "both: missing podname",
			requireNamespace: true,
			requirePodname:   true,
			paramValues:      map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			expectError:      true,
		},
		{
			name:             "both: missing namespace",
			requireNamespace: true,
			requirePodname:   true,
			paramValues:      map[string]string{operatorFilterParamKey: "k8s.podname~nginx-abc"},
			expectError:      true,
		},
		{
			name:             "both: nil params",
			requireNamespace: true,
			requirePodname:   true,
			paramValues:      nil,
			expectError:      true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := &Service{
				requireNamespace: tc.requireNamespace,
				requirePodname:   tc.requirePodname,
			}
			err := svc.validateFilterParams(tc.paramValues)
			if tc.expectError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestNamespaceFromFilterParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		paramValues map[string]string
		wantNS      string
		wantErr     bool
	}{
		{
			name:        "single namespace in global filter",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default,pid==1"},
			wantNS:      "default",
		},
		{
			name:        "single namespace in datasource-scoped filter",
			paramValues: map[string]string{operatorFilterParamKey + ".events": "k8s.namespace==kube-system"},
			wantNS:      "kube-system",
		},
		{
			name:        "missing namespace",
			paramValues: map[string]string{operatorFilterParamKey: "pid==1"},
			wantErr:     true,
		},
		{
			name:        "invalid namespace value",
			paramValues: map[string]string{operatorFilterParamKey: "k8s.namespace==my.ns"},
			wantErr:     true,
		},
		{
			name: "multiple different namespaces",
			paramValues: map[string]string{
				operatorFilterParamKey: "k8s.namespace==default,k8s.namespace==kube-system",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotNS, err := namespaceFromFilterParams(tc.paramValues)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if gotNS != tc.wantNS {
				t.Fatalf("namespaceFromFilterParams() = %q, want %q", gotNS, tc.wantNS)
			}
		})
	}
}

func TestValidateRequestTokenListCRDPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		request             *api.GadgetRunRequest
		authzErr            error
		validationEnabled   bool
		expectCheckerCalled bool
		expectError         bool
		errorContains       string
	}{
		{
			name: "no token skips check",
			request: &api.GadgetRunRequest{
				ParamValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			},
			validationEnabled:   true,
			expectCheckerCalled: false,
			expectError:         false,
		},
		{
			name: "validation disabled skips check",
			request: &api.GadgetRunRequest{
				Token:       "TOKEN-SIMONE",
				ParamValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			},
			validationEnabled:   false,
			expectCheckerCalled: false,
			expectError:         false,
		},
		{
			name: "token with valid namespace passes",
			request: &api.GadgetRunRequest{
				Args:        []string{"TOKEN-SIMONE"},
				ParamValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			},
			validationEnabled:   true,
			expectCheckerCalled: true,
			expectError:         false,
		},
		{
			name: "token but missing namespace fails",
			request: &api.GadgetRunRequest{
				Args:        []string{"TOKEN-SIMONE"},
				ParamValues: map[string]string{operatorFilterParamKey: "pid==1"},
			},
			validationEnabled:   true,
			expectCheckerCalled: false,
			expectError:         true,
			errorContains:       "resolving namespace",
		},
		{
			name: "token with denied authz fails",
			request: &api.GadgetRunRequest{
				Token:       "TOKEN-SIMONE",
				ParamValues: map[string]string{operatorFilterParamKey: "k8s.namespace==default"},
			},
			authzErr:            errors.New("forbidden"),
			validationEnabled:   true,
			expectCheckerCalled: true,
			expectError:         true,
			errorContains:       "not authorized to list",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkerCalled := false
			svc := &Service{validateToken: tc.validationEnabled}
			svc.tokenListCRDAuthzChecker = func(_ context.Context, token, namespace string) error {
				checkerCalled = true
				if token == "" {
					t.Fatalf("expected non-empty token")
				}
				if namespace != "default" {
					t.Fatalf("expected namespace default, got %q", namespace)
				}
				return tc.authzErr
			}

			err := svc.validateRequestTokenListCRDPermission(context.Background(), tc.request)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Fatalf("expected error containing %q, got %v", tc.errorContains, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if checkerCalled != tc.expectCheckerCalled {
				t.Fatalf("checkerCalled = %v, want %v", checkerCalled, tc.expectCheckerCalled)
			}
		})
	}
}

func TestEffectiveTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		maxTTL         time.Duration
		requestTimeout time.Duration
		wantTimeout    time.Duration
	}{
		{
			name:           "max ttl disabled keeps request timeout",
			maxTTL:         0,
			requestTimeout: 10 * time.Second,
			wantTimeout:    10 * time.Second,
		},
		{
			name:           "request timeout lower than max ttl keeps request timeout",
			maxTTL:         30 * time.Second,
			requestTimeout: 10 * time.Second,
			wantTimeout:    10 * time.Second,
		},
		{
			name:           "request timeout higher than max ttl is capped",
			maxTTL:         20 * time.Second,
			requestTimeout: 90 * time.Second,
			wantTimeout:    20 * time.Second,
		},
		{
			name:           "request timeout missing uses max ttl",
			maxTTL:         45 * time.Second,
			requestTimeout: 0,
			wantTimeout:    45 * time.Second,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := &Service{gadgetMaxTTL: tc.maxTTL}
			got := svc.effectiveTimeout(tc.requestTimeout)
			if got != tc.wantTimeout {
				t.Fatalf("effectiveTimeout() = %v, want %v", got, tc.wantTimeout)
			}
		})
	}
}
