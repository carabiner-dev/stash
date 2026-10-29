package client

import "testing"

func TestNormalizeNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{
			name:      "empty namespace stays empty",
			namespace: "",
			want:      "",
		},
		{
			name:      "named namespace stays as-is",
			namespace: "production",
			want:      "production",
		},
		{
			name:      "underscore stays as underscore",
			namespace: "_",
			want:      "_",
		},
		{
			name:      "wildcard stays as wildcard",
			namespace: "*",
			want:      "*",
		},
		{
			name:      "app namespace",
			namespace: "app",
			want:      "app",
		},
		{
			name:      "a repository's namespace travels as one segment",
			namespace: "repository:acme/github/acme-gh/widgets",
			want:      "repository:acme%2Fgithub%2Facme-gh%2Fwidgets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeNamespace(tt.namespace)
			if got != tt.want {
				t.Errorf("normalizeNamespace(%q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}
