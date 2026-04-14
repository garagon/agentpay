package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CompromisedPackage describes a known-bad npm package+version.
// Detection logic adapted from the Aguara engine (github.com/garagon/aguara).
type CompromisedPackage struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	Advisory string   `json:"advisory"`
	Date     string   `json:"date"`
	Summary  string   `json:"summary"`
}

// KnownCompromised is the embedded list of known compromised npm packages.
var KnownCompromised = []CompromisedPackage{
	{
		Name:     "axios",
		Versions: []string{"1.7.8", "1.7.9"},
		Advisory: "GHSA-axios-2026-04",
		Date:     "2026-04-10",
		Summary:  "Compromised axios versions exfiltrate environment variables and auth tokens via postinstall script to attacker-controlled endpoint",
	},
}

// IsCompromisedPkg checks if an npm package name+version is known-bad.
func IsCompromisedPkg(name, version string) *CompromisedPackage {
	lower := strings.ToLower(name)
	for i := range KnownCompromised {
		if KnownCompromised[i].Name != lower {
			continue
		}
		for _, v := range KnownCompromised[i].Versions {
			if v == version {
				return &KnownCompromised[i]
			}
		}
	}
	return nil
}

// ScanFinding represents a compromised package found on disk.
type ScanFinding struct {
	Severity string `json:"severity"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Path     string `json:"path"`
	Advisory string `json:"advisory"`
	Summary  string `json:"summary"`
}

// ScanResult holds all findings from a scan run.
type ScanResult struct {
	ScannedDirs int           `json:"scanned_dirs"`
	Findings    []ScanFinding `json:"findings"`
}

// ScanNodeModules walks a directory tree looking for compromised npm packages
// by reading package.json files in node_modules.
func ScanNodeModules(root string) (*ScanResult, error) {
	result := &ScanResult{}

	// Find all node_modules directories.
	var nmDirs []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == "node_modules" {
			nmDirs = append(nmDirs, path)
			return filepath.SkipDir
		}
		// Also check top-level package-lock.json for locked versions.
		if !d.IsDir() && d.Name() == "package-lock.json" {
			if findings := scanLockfile(path); len(findings) > 0 {
				result.Findings = append(result.Findings, findings...)
			}
		}
		return nil
	})

	for _, nmDir := range nmDirs {
		entries, err := os.ReadDir(nmDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			result.ScannedDirs++
			pkgJSON := filepath.Join(nmDir, entry.Name(), "package.json")
			name, version := readPkgJSON(pkgJSON)
			if name == "" {
				continue
			}
			if cp := IsCompromisedPkg(name, version); cp != nil {
				result.Findings = append(result.Findings, ScanFinding{
					Severity: "CRITICAL",
					Package:  cp.Name,
					Version:  version,
					Path:     filepath.Join(nmDir, entry.Name()),
					Advisory: cp.Advisory,
					Summary:  cp.Summary,
				})
			}
		}
	}

	return result, nil
}

// CleanFindings removes compromised packages found by ScanNodeModules.
// Moves them to a quarantine directory for forensic review.
func CleanFindings(findings []ScanFinding, dryRun bool) []CleanActionResult {
	ts := time.Now().Format("2006-01-02T150405.000000000")
	quarantine := filepath.Join(os.TempDir(), "agentpay-quarantine", ts)

	var actions []CleanActionResult
	for i, f := range findings {
		action := CleanActionResult{
			Package: f.Package,
			Version: f.Version,
			Path:    f.Path,
		}
		if dryRun {
			action.Action = "would remove"
		} else {
			if err := os.MkdirAll(quarantine, 0700); err != nil {
				action.Action = "failed"
				action.Error = err.Error()
				actions = append(actions, action)
				continue
			}
			dst := filepath.Join(quarantine, quarantineEntryName(f, i))
			if err := os.Rename(f.Path, dst); err != nil {
				action.Action = "failed"
				action.Error = err.Error()
			} else {
				action.Action = "quarantined"
				action.Destination = dst
			}
		}
		actions = append(actions, action)
	}
	return actions
}

// CleanActionResult describes what happened to a compromised package.
type CleanActionResult struct {
	Package     string `json:"package"`
	Version     string `json:"version"`
	Path        string `json:"path"`
	Action      string `json:"action"`
	Destination string `json:"destination,omitempty"`
	Error       string `json:"error,omitempty"`
}

// quarantineEntryName builds a unique destination name for each finding,
// combining package, version, index, and the basename of the source path
// to avoid collisions when the same package appears in multiple locations
// (e.g. node_modules/axios AND package-lock.json).
func quarantineEntryName(f ScanFinding, index int) string {
	base := filepath.Base(f.Path)
	return fmt.Sprintf("%s-%s-%d-%s", f.Package, f.Version, index, base)
}

func readPkgJSON(path string) (name, version string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", ""
	}
	return strings.ToLower(pkg.Name), pkg.Version
}

func scanLockfile(path string) []ScanFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}

	var findings []ScanFinding

	// npm v3 lockfile format (packages).
	for key, pkg := range lock.Packages {
		name := key
		if strings.HasPrefix(name, "node_modules/") {
			name = strings.TrimPrefix(name, "node_modules/")
		}
		if cp := IsCompromisedPkg(name, pkg.Version); cp != nil {
			findings = append(findings, ScanFinding{
				Severity: "CRITICAL",
				Package:  cp.Name,
				Version:  pkg.Version,
				Path:     path,
				Advisory: cp.Advisory,
				Summary:  cp.Summary + " (found in lockfile)",
			})
		}
	}

	// npm v1 lockfile format (dependencies).
	for name, dep := range lock.Dependencies {
		if cp := IsCompromisedPkg(name, dep.Version); cp != nil {
			findings = append(findings, ScanFinding{
				Severity: "CRITICAL",
				Package:  cp.Name,
				Version:  dep.Version,
				Path:     path,
				Advisory: cp.Advisory,
				Summary:  cp.Summary + " (found in lockfile)",
			})
		}
	}

	return findings
}
