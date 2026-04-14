package main

import "testing"

func TestScanCredentials(t *testing.T) {
	tests := []struct {
		name     string
		args     map[string]any
		wantType string
		wantNil  bool
	}{
		{
			name:    "clean args",
			args:    map[string]any{"amount": 50.0, "recipient": "alice@co.com"},
			wantNil: true,
		},
		{
			name:     "anthropic key",
			args:     map[string]any{"note": "ref: sk-ant-abc123def456ghi789jkl"},
			wantType: "Anthropic API key",
		},
		{
			name:     "openai key",
			args:     map[string]any{"description": "sk-proj-abcdef1234567890"},
			wantType: "OpenAI API key",
		},
		{
			name:     "github pat",
			args:     map[string]any{"memo": "ghp_abcdef1234567890"},
			wantType: "GitHub personal access token",
		},
		{
			name:     "aws access key",
			args:     map[string]any{"ref": "AKIAIOSFODNN7EXAMPLE"},
			wantType: "AWS access key",
		},
		{
			name:     "slack token",
			args:     map[string]any{"token": "xoxb-123456789-abcdefghij"},
			wantType: "Slack token",
		},
		{
			name:     "jwt token",
			args:     map[string]any{"auth": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
			wantType: "JWT",
		},
		{
			name:     "private key header",
			args:     map[string]any{"key": "-----BEGIN RSA PRIVATE KEY-----"},
			wantType: "Private key",
		},
		{
			name: "nested credential",
			args: map[string]any{
				"metadata": map[string]any{
					"secret": "ghp_abcdef1234567890",
				},
			},
			wantType: "GitHub personal access token",
		},
		{
			name: "credential in array",
			args: map[string]any{
				"tags": []any{"normal", "sk-ant-abc123def456ghi789jkl"},
			},
			wantType: "Anthropic API key",
		},
		{
			name:     "sendgrid key",
			args:     map[string]any{"api_key": "SG.abcdefghij1234567890"},
			wantType: "SendGrid API key",
		},
		{
			name:     "gitlab pat",
			args:     map[string]any{"token": "glpat-abcdefghij1234567890"},
			wantType: "GitLab PAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := ScanCredentials(tt.args)
			if tt.wantNil {
				if match != nil {
					t.Errorf("expected nil, got %+v", match)
				}
				return
			}
			if match == nil {
				t.Fatal("expected match, got nil")
			}
			if match.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", match.Type, tt.wantType)
			}
			// Verify redaction doesn't expose full credential.
			if len(match.Redacted) > 13 {
				t.Errorf("Redacted value too long (%d chars): %q", len(match.Redacted), match.Redacted)
			}
		})
	}
}

func TestRedactValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sk-ant-abc123def456ghi789jkl", "sk-ant-abc***"},
		{"short", "shor***"},
		{"ab", "***"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactValue(tt.input)
			if got != tt.want {
				t.Errorf("redactValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
