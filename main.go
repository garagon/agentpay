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
