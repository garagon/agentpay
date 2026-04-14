package main

import (
	"fmt"
	"regexp"
)

// CredentialMatch describes a credential found in tool arguments.
type CredentialMatch struct {
	Type     string // e.g. "Anthropic API key", "AWS access key"
	Field    string // JSON field path where it was found
	Redacted string // value truncated for safe logging
}

// credentialPattern pairs a compiled regex with a human-readable type name.
type credentialPattern struct {
	re       *regexp.Regexp
	typeName string
}

var credentialPatterns = []credentialPattern{
	{regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{10,}`), "Anthropic API key"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9_-]{10,}`), "OpenAI API key"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{10,}`), "GitHub personal access token"},
	{regexp.MustCompile(`gho_[a-zA-Z0-9]{10,}`), "GitHub OAuth token"},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]{10,}`), "GitHub server token"},
	{regexp.MustCompile(`ghr_[a-zA-Z0-9]{10,}`), "GitHub refresh token"},
	{regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{10,}`), "GitHub fine-grained PAT"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{4,}`), "AWS access key"},
	{regexp.MustCompile(`xox[bpas]-[a-zA-Z0-9-]{10,}`), "Slack token"},
	{regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{10,}`), "GitLab PAT"},
	{regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{10,}`), "SendGrid API key"},
	{regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`), "Private key"},
	{regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}`), "JWT"},
}

// ScanCredentials recursively scans all string values in a tool_input map
// for known credential patterns. Returns the first match found.
func ScanCredentials(args map[string]any) *CredentialMatch {
	return scanMap(args, "")
}

func scanMap(m map[string]any, prefix string) *CredentialMatch {
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if match := scanValue(v, path); match != nil {
			return match
		}
	}
	return nil
}

func scanValue(v any, path string) *CredentialMatch {
	switch val := v.(type) {
	case string:
		return scanString(val, path)
	case map[string]any:
		return scanMap(val, path)
	case []any:
		for i, item := range val {
			p := fmt.Sprintf("%s[%d]", path, i)
			if match := scanValue(item, p); match != nil {
				return match
			}
		}
	}
	return nil
}

func scanString(s, path string) *CredentialMatch {
	for _, cp := range credentialPatterns {
		loc := cp.re.FindStringIndex(s)
		if loc == nil {
			continue
		}
		matched := s[loc[0]:loc[1]]
		return &CredentialMatch{
			Type:     cp.typeName,
			Field:    path,
			Redacted: redactValue(matched),
		}
	}
	return nil
}

// redactValue truncates a credential to its first 10 characters followed by
// "***" to prevent leaking secrets in logs or error messages.
func redactValue(s string) string {
	if len(s) > 10 {
		return s[:10] + "***"
	}
	if len(s) > 4 {
		return s[:4] + "***"
	}
	return "***"
}
