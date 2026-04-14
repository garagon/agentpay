package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

func main() {
	root := &cobra.Command{
		Use:   "agentpay",
		Short: "Payment security plugin for Claude Code",
		Long: `AgentPay intercepts financial tool calls in Claude Code, detects payment
manipulation from compromised MCP servers, and blocks fraud before money moves.

Install as a Claude Code plugin with: agentpay install`,
		SilenceUsage: true,
	}

	root.AddCommand(
		newInstallCmd(),
		newUninstallCmd(),
		newGuardCmd(),
		newAuditCmd(),
		newScanCmd(),
		newCleanCmd(),
		newDemoCmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install AgentPay as a Claude Code plugin",
		RunE: func(cmd *cobra.Command, args []string) error {
			configDir := DefaultConfigDir()
			settingsPath := DefaultSettingsPath()

			hookCmd, err := resolveHookCommand()
			if err != nil {
				return err
			}

			if err := Install(configDir, settingsPath); err != nil {
				return err
			}

			fmt.Println()
			fmt.Println("  AgentPay installed successfully.")
			fmt.Println()
			fmt.Printf("  Hook:   PreToolUse -> %s\n", hookCmd)
			fmt.Printf("  Config: %s/policy.yaml\n", configDir)
			fmt.Printf("  Audit:  %s/audit.jsonl\n", configDir)
			fmt.Println()
			fmt.Println("  Restart Claude Code to activate.")
			fmt.Println()
			return nil
		},
	}
}

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove AgentPay from Claude Code",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := Uninstall(DefaultSettingsPath()); err != nil {
				return err
			}
			fmt.Println("AgentPay removed.")
			fmt.Println("  Hook removed from Claude Code settings.")
			fmt.Printf("  Config preserved at %s\n", DefaultConfigDir())
			return nil
		},
	}
}

func newGuardCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "guard",
		Short:  "PreToolUse hook handler (called by Claude Code)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}

			var input HookInput
			if err := json.Unmarshal(data, &input); err != nil {
				// If we can't parse the input, allow the tool call
				// (fail-open to avoid blocking non-standard tools).
				return nil
			}

			pipeline, err := NewPipeline(DefaultConfigDir())
			if err != nil {
				// Fail-open: allow the tool call if pipeline fails to init.
				return nil
			}
			defer pipeline.Close()

			_, output := pipeline.Run(input)

			// Non-financial tools: no output (implicit allow).
			if output.HookSpecificOutput == nil {
				return nil
			}
			// Non-financial allow: silent pass-through.
			if output.HookSpecificOutput.PermissionDecision == "allow" &&
				output.HookSpecificOutput.AdditionalContext == "" {
				return nil
			}

			return json.NewEncoder(os.Stdout).Encode(output)
		},
	}
}

func newAuditCmd() *cobra.Command {
	var verify bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show payment audit trail",
		RunE: func(cmd *cobra.Command, args []string) error {
			return PrintAudit(DefaultConfigDir(), verify)
		},
	}
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify hash chain integrity")
	return cmd
}

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan for compromised npm packages (axios supply chain attack)",
		Long: `Scans node_modules and package-lock.json for known compromised packages.
Currently detects the axios supply chain attack (versions 1.7.8, 1.7.9).

Detection engine adapted from Aguara (github.com/garagon/aguara).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			fmt.Printf("\n%s%sAgentPay Supply Chain Scanner%s\n", colorBold, colorCyan, colorReset)
			fmt.Printf("%sPowered by Aguara detection engine%s\n\n", colorDim, colorReset)
			fmt.Printf("Scanning %s ...\n\n", root)

			result, err := ScanNodeModules(root)
			if err != nil {
				return err
			}

			fmt.Printf("  Packages scanned: %d\n", result.ScannedDirs)

			if len(result.Findings) == 0 {
				fmt.Printf("\n  %sNo compromised packages found.%s\n\n", colorGreen, colorReset)
				return nil
			}

			fmt.Printf("\n  %s%sFOUND %d compromised package(s):%s\n\n",
				colorBold, colorRed, len(result.Findings), colorReset)

			for _, f := range result.Findings {
				fmt.Printf("  %s[%s]%s %s@%s\n", colorRed, f.Severity, colorReset, f.Package, f.Version)
				fmt.Printf("    Advisory: %s\n", f.Advisory)
				fmt.Printf("    Summary:  %s\n", f.Summary)
				fmt.Printf("    Path:     %s\n\n", f.Path)
			}

			fmt.Printf("  Run %sagentpay clean%s to quarantine compromised packages.\n\n", colorBold, colorReset)
			return nil
		},
	}
}

func newCleanCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "clean [path]",
		Short: "Remove compromised npm packages (quarantine to /tmp)",
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			result, err := ScanNodeModules(root)
			if err != nil {
				return err
			}

			if len(result.Findings) == 0 {
				fmt.Printf("\n  %sNo compromised packages found. Nothing to clean.%s\n\n", colorGreen, colorReset)
				return nil
			}

			if dryRun {
				fmt.Printf("\n  %s[DRY RUN]%s Would quarantine %d package(s):\n\n", colorYellow, colorReset, len(result.Findings))
			} else {
				fmt.Printf("\n  %sQuarantining %d compromised package(s):%s\n\n", colorBold, len(result.Findings), colorReset)
			}

			actions := CleanFindings(result.Findings, dryRun)
			for _, a := range actions {
				switch a.Action {
				case "quarantined":
					fmt.Printf("  %s[QUARANTINED]%s %s@%s\n", colorGreen, colorReset, a.Package, a.Version)
					fmt.Printf("    From: %s\n", a.Path)
					fmt.Printf("    To:   %s\n\n", a.Destination)
				case "would remove":
					fmt.Printf("  %s[WOULD REMOVE]%s %s@%s\n", colorYellow, colorReset, a.Package, a.Version)
					fmt.Printf("    Path: %s\n\n", a.Path)
				case "failed":
					fmt.Printf("  %s[FAILED]%s %s@%s: %s\n\n", colorRed, colorReset, a.Package, a.Version, a.Error)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed without removing")
	return cmd
}

func newDemoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "demo",
		Short: "Run interactive demo with attack scenarios",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDemo()
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("agentpay %s\n", version)
		},
	}
}
