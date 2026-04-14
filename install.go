package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pluginName = "agentpay"

// resolvePluginRoot returns the directory containing .claude-plugin/.
// This is the root of the AgentPay project.
func resolvePluginRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	abs, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return filepath.Dir(abs), nil
}

// resolveHookCommand returns the absolute path to this binary + " guard".
func resolveHookCommand() (string, error) {
	root, err := resolvePluginRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "agentpay-bin guard"), nil
}

// Install registers AgentPay as a Claude Code plugin and creates
// the config directory with default policy.
func Install(configDir, settingsPath string) error {
	pluginRoot, err := resolvePluginRoot()
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

	// Register as Claude Code plugin.
	if err := registerPlugin(settingsPath, pluginRoot); err != nil {
		return fmt.Errorf("register plugin: %w", err)
	}

	// Clean up old hook-style install if present.
	cleanLegacyHook(settingsPath)

	return nil
}

// Uninstall removes AgentPay from Claude Code.
func Uninstall(settingsPath string) error {
	if err := unregisterPlugin(settingsPath); err != nil {
		return err
	}
	cleanLegacyHook(settingsPath)
	return nil
}

// registerPlugin adds AgentPay to installed_plugins.json and enables it
// in settings.json, making it appear in Claude Code's plugin list.
func registerPlugin(settingsPath, pluginRoot string) error {
	home, _ := os.UserHomeDir()

	// 1. Add to installed_plugins.json.
	ipPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	if err := addInstalledPlugin(ipPath, pluginRoot); err != nil {
		return err
	}

	// 2. Enable in settings.json.
	settings, err := readSettings(settingsPath)
	if err != nil {
		return err
	}

	enabled, _ := settings["enabledPlugins"].(map[string]any)
	if enabled == nil {
		enabled = make(map[string]any)
		settings["enabledPlugins"] = enabled
	}
	enabled[pluginName+"@local"] = true

	return writeSettings(settingsPath, settings)
}

// unregisterPlugin removes AgentPay from plugin registries.
func unregisterPlugin(settingsPath string) error {
	home, _ := os.UserHomeDir()

	// Remove from installed_plugins.json.
	ipPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	removeInstalledPlugin(ipPath)

	// Disable in settings.json.
	settings, err := readSettings(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if enabled, ok := settings["enabledPlugins"].(map[string]any); ok {
		delete(enabled, pluginName+"@local")
		if len(enabled) == 0 {
			delete(settings, "enabledPlugins")
		}
	}
	return writeSettings(settingsPath, settings)
}

// addInstalledPlugin writes to installed_plugins.json.
func addInstalledPlugin(path, pluginRoot string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	var data map[string]any
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &data)
	}
	if data == nil {
		data = map[string]any{"version": float64(2)}
	}

	plugins, _ := data["plugins"].(map[string]any)
	if plugins == nil {
		plugins = make(map[string]any)
		data["plugins"] = plugins
	}

	key := pluginName + "@local"
	plugins[key] = []any{
		map[string]any{
			"scope":       "user",
			"installPath": pluginRoot,
			"version":     version,
			"installedAt": time.Now().UTC().Format(time.RFC3339),
			"lastUpdated": time.Now().UTC().Format(time.RFC3339),
		},
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}

// removeInstalledPlugin removes AgentPay from installed_plugins.json.
func removeInstalledPlugin(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}
	plugins, _ := data["plugins"].(map[string]any)
	if plugins == nil {
		return
	}
	delete(plugins, pluginName+"@local")
	out, _ := json.MarshalIndent(data, "", "  ")
	_ = os.WriteFile(path, append(out, '\n'), 0600)
}

// cleanLegacyHook removes old hook-style AgentPay entries from settings.json
// (from versions before plugin registration).
func cleanLegacyHook(settingsPath string) {
	settings, err := readSettings(settingsPath)
	if err != nil {
		return
	}
	if removeHook(settings) {
		_ = writeSettings(settingsPath, settings)
	}
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

// isAgentPayHook identifies legacy hook entries to clean up.
func isAgentPayHook(cmd string) bool {
	return cmd == "agentpay guard" ||
		strings.HasSuffix(cmd, "/agentpay guard") ||
		strings.HasSuffix(cmd, "/agentpay-bin guard")
}

// removeHook removes legacy AgentPay hook entries from settings.
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
