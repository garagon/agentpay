package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	pluginName      = "agentpay"
	marketplaceName = "agentpay"
	marketplaceRepo = "garagon/agentpay"
)

func pluginKey() string {
	return pluginName + "@" + marketplaceName
}

// resolvePluginRoot returns the directory containing .claude-plugin/.
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

// Install registers AgentPay as a Claude Code plugin globally.
func Install(configDir, settingsPath string) error {
	pluginRoot, err := resolvePluginRoot()
	if err != nil {
		return err
	}

	home, _ := os.UserHomeDir()
	claudeDir := filepath.Join(home, ".claude")

	// Create config directory with default policy.
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	policyPath := filepath.Join(configDir, "policy.yaml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		if err := SavePolicy(policyPath, DefaultPolicy()); err != nil {
			return fmt.Errorf("write default policy: %w", err)
		}
	}

	// 1. Create cache symlink (how Claude Code expects to find plugins).
	cachePath := filepath.Join(claudeDir, "plugins", "cache", marketplaceName, pluginName, version)
	if err := createCacheLink(cachePath, pluginRoot); err != nil {
		return fmt.Errorf("create cache: %w", err)
	}

	// 2. Register marketplace in known_marketplaces.json.
	kmPath := filepath.Join(claudeDir, "plugins", "known_marketplaces.json")
	if err := registerMarketplace(kmPath, pluginRoot); err != nil {
		return fmt.Errorf("register marketplace: %w", err)
	}

	// 3. Add to installed_plugins.json.
	ipPath := filepath.Join(claudeDir, "plugins", "installed_plugins.json")
	if err := addInstalledPlugin(ipPath, cachePath); err != nil {
		return fmt.Errorf("add installed plugin: %w", err)
	}

	// 4. Enable in settings.json.
	settings, err := readSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	enabled, _ := settings["enabledPlugins"].(map[string]any)
	if enabled == nil {
		enabled = make(map[string]any)
		settings["enabledPlugins"] = enabled
	}
	enabled[pluginKey()] = true
	// Clean old entries.
	delete(enabled, pluginName+"@local")
	if err := writeSettings(settingsPath, settings); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}

	// 5. Clean legacy hook entries.
	cleanLegacyHook(settingsPath)

	return nil
}

// Uninstall removes AgentPay from Claude Code.
func Uninstall(settingsPath string) error {
	home, _ := os.UserHomeDir()
	claudeDir := filepath.Join(home, ".claude")

	// Remove cache.
	cachePath := filepath.Join(claudeDir, "plugins", "cache", marketplaceName)
	os.RemoveAll(cachePath)

	// Remove from installed_plugins.json.
	ipPath := filepath.Join(claudeDir, "plugins", "installed_plugins.json")
	removeInstalledPlugin(ipPath)

	// Remove from known_marketplaces.json.
	kmPath := filepath.Join(claudeDir, "plugins", "known_marketplaces.json")
	removeMarketplace(kmPath)

	// Disable in settings.json.
	settings, err := readSettings(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if enabled, ok := settings["enabledPlugins"].(map[string]any); ok {
		delete(enabled, pluginKey())
		delete(enabled, pluginName+"@local")
	}
	if mkt, ok := settings["extraKnownMarketplaces"].(map[string]any); ok {
		delete(mkt, marketplaceName)
	}
	if err := writeSettings(settingsPath, settings); err != nil {
		return err
	}

	cleanLegacyHook(settingsPath)
	return nil
}

// createCacheLink creates a symlink in Claude Code's plugin cache pointing
// to the actual plugin directory.
func createCacheLink(cachePath, pluginRoot string) error {
	parent := filepath.Dir(cachePath)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	// Remove old link/dir if exists.
	os.RemoveAll(cachePath)
	return os.Symlink(pluginRoot, cachePath)
}

// registerMarketplace adds our marketplace to known_marketplaces.json.
func registerMarketplace(path, pluginRoot string) error {
	var data map[string]any
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &data)
	}
	if data == nil {
		data = make(map[string]any)
	}

	data[marketplaceName] = map[string]any{
		"source": map[string]any{
			"source": "github",
			"repo":   marketplaceRepo,
		},
		"installLocation": pluginRoot,
		"lastUpdated":     time.Now().UTC().Format(time.RFC3339Nano),
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}

// removeMarketplace removes from known_marketplaces.json.
func removeMarketplace(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return
	}
	delete(data, marketplaceName)
	out, _ := json.MarshalIndent(data, "", "  ")
	_ = os.WriteFile(path, append(out, '\n'), 0600)
}

// addInstalledPlugin writes to installed_plugins.json.
func addInstalledPlugin(path, installPath string) error {
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
	// Clean old format.
	delete(plugins, pluginName+"@local")

	now := time.Now().UTC().Format(time.RFC3339)
	plugins[pluginKey()] = []any{
		map[string]any{
			"scope":       "user",
			"installPath": installPath,
			"version":     version,
			"installedAt": now,
			"lastUpdated": now,
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
	if json.Unmarshal(raw, &data) != nil {
		return
	}
	plugins, _ := data["plugins"].(map[string]any)
	if plugins == nil {
		return
	}
	delete(plugins, pluginKey())
	delete(plugins, pluginName+"@local")
	out, _ := json.MarshalIndent(data, "", "  ")
	_ = os.WriteFile(path, append(out, '\n'), 0600)
}

// cleanLegacyHook removes old hook-style AgentPay entries.
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

func isAgentPayHook(cmd string) bool {
	return cmd == "agentpay guard" ||
		strings.HasSuffix(cmd, "/agentpay guard") ||
		strings.HasSuffix(cmd, "/agentpay-bin guard")
}

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
