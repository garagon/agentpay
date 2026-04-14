package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hookCommandSuffix is appended to the binary path in the hook config.
const hookCommandSuffix = " guard"

// resolveHookCommand returns the absolute path to this binary + " guard".
// Using the absolute path means the hook works regardless of the user's PATH.
func resolveHookCommand() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	abs, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return abs + hookCommandSuffix, nil
}

// Install adds the AgentPay PreToolUse hook to Claude Code's settings.json
// and creates the config directory with default policy.
func Install(configDir, settingsPath string) error {
	hookCmd, err := resolveHookCommand()
	if err != nil {
		return err
	}

	// Create config directory.
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Write default policy if it doesn't exist.
	policyPath := filepath.Join(configDir, "policy.yaml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		if err := SavePolicy(policyPath, DefaultPolicy()); err != nil {
			return fmt.Errorf("write default policy: %w", err)
		}
	}

	// Read existing settings.
	settings, err := readSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}

	// Add PreToolUse hook with absolute path.
	if addHook(settings, hookCmd) {
		if err := writeSettings(settingsPath, settings); err != nil {
			return fmt.Errorf("write settings: %w", err)
		}
	}

	return nil
}

// Uninstall removes the AgentPay hook from Claude Code's settings.json.
// Config directory is preserved.
func Uninstall(settingsPath string) error {
	settings, err := readSettings(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read settings: %w", err)
	}

	if removeHook(settings) {
		if err := writeSettings(settingsPath, settings); err != nil {
			return fmt.Errorf("write settings: %w", err)
		}
	}
	return nil
}

// DefaultSettingsPath returns the path to Claude Code's user settings.
func DefaultSettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

// DefaultConfigDir returns the AgentPay config directory path.
func DefaultConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentpay")
}

func readSettings(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]any), nil
		}
		return nil, err
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}
	return settings, nil
}

func writeSettings(path string, settings map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// isAgentPayHook returns true if the hook command is an agentpay guard command.
func isAgentPayHook(cmd string) bool {
	// Match both relative ("agentpay guard") and absolute ("/path/to/agentpay guard").
	return cmd == "agentpay guard" || strings.HasSuffix(cmd, "/agentpay guard")
}

// addHook inserts the AgentPay PreToolUse hook into settings. Returns
// true if settings were modified.
func addHook(settings map[string]any, hookCmd string) bool {
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = make(map[string]any)
		settings["hooks"] = hooks
	}

	preToolUse, _ := hooks["PreToolUse"].([]any)

	// Check if already installed (handles both old relative and new absolute paths).
	for _, entry := range preToolUse {
		m, _ := entry.(map[string]any)
		innerHooks, _ := m["hooks"].([]any)
		for _, h := range innerHooks {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); isAgentPayHook(cmd) {
				return false
			}
		}
	}

	// Append our hook entry with absolute path.
	entry := map[string]any{
		"matcher": "",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": hookCmd,
			},
		},
	}
	hooks["PreToolUse"] = append(preToolUse, entry)
	return true
}

// removeHook removes the AgentPay hook from settings. Returns true if
// settings were modified.
func removeHook(settings map[string]any) bool {
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return false
	}
	preToolUse, _ := hooks["PreToolUse"].([]any)
	if preToolUse == nil {
		return false
	}

	var filtered []any
	modified := false
	for _, entry := range preToolUse {
		m, _ := entry.(map[string]any)
		innerHooks, _ := m["hooks"].([]any)
		isOurs := false
		for _, h := range innerHooks {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); isAgentPayHook(cmd) {
				isOurs = true
				break
			}
		}
		if isOurs {
			modified = true
		} else {
			filtered = append(filtered, entry)
		}
	}

	if modified {
		if len(filtered) == 0 {
			delete(hooks, "PreToolUse")
			if len(hooks) == 0 {
				delete(settings, "hooks")
			}
		} else {
			hooks["PreToolUse"] = filtered
		}
	}
	return modified
}
