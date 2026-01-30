package client

import "testing"

func TestNormalizeNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{
			name:      "empty namespace converts to underscore",
			namespace: "",
			want:      "_",
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
