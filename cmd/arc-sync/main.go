package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/comma-compliance/arc-relay/internal/cli/config"
	"github.com/comma-compliance/arc-relay/internal/cli/project"
	"github.com/comma-compliance/arc-relay/internal/cli/relay"
	"github.com/comma-compliance/arc-relay/internal/cli/safety"
	"github.com/comma-compliance/arc-relay/internal/cli/sync"
)

//go:embed skill.md
var embeddedSkillMD []byte

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		runSync()
		return
	}

	switch os.Args[1] {
	case "init":
		runInit()
	case "list":
		runList()
	case "add":
		runAdd()
	case "remove", "rm":
		runRemove()
	case "reset":
		runReset()
	case "status":
		runStatus()
	case "server":
		runServer()
	case "setup-claude":
		runSetupClaude()
	case "setup-codex":
		runSetupCodex()
	case "setup-project":
		runSetupProject()
	case "--version", "version":
		fmt.Printf("arc-sync %s\n", version)
	case "--help", "help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: arc-sync [command]

Commands:
  (none)        Interactive sync — add relay servers to current project
  init          Configure relay URL and API key (--token with --username/--password for invites)
  list          Show all available servers and project status
  add <name>    Add a specific server to the current project
  remove <name> Remove a server from the current project (and skip it)
  reset         Clear the skip list for the current project
  status        Show configuration and project details
  setup-claude  Install Claude Code skill and instructions
  setup-codex   Install Codex CLI AGENTS instructions
  setup-project Add project MCP instructions to .claude/CLAUDE.md and AGENTS.md
  server        Manage servers on the relay instance (add, remove, start, stop)

Flags (for sync/add):
  --non-interactive, -y    Auto-accept all new servers
  --dry-run                Show what would change without writing files
  --json                   Output in JSON format
  --project <path>         Override project directory detection
  --config <path>          Override config directory

Environment variables:
  ARC_SYNC_URL       Relay URL (overrides config file)
  ARC_SYNC_API_KEY   API key (overrides config file)
  ARC_SYNC_CONFIG    Config directory path

Run 'arc-sync server --help' for server management commands.`)
}

func getConfigDir() string {
	// Check flag
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	// Check env
	if dir := os.Getenv("ARC_SYNC_CONFIG"); dir != "" {
		return dir
	}
	// Default
	dir, err := config.DefaultConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return dir
}

func getProjectDir() string {
	// Check flag
	for i, arg := range os.Args {
		if arg == "--project" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	// Detect from CWD
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine current directory: %v\n", err)
		os.Exit(1)
	}
	dir, err := project.DetectProjectDir(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return dir
}

func hasFlag(name string) bool {
	for _, arg := range os.Args {
		if arg == name {
			return true
		}
	}
	return false
}

func runSync() {
	configDir := getConfigDir()
	projectDir := getProjectDir()

	_, err := sync.Run(sync.Options{
		ConfigDir:      configDir,
		ProjectDir:     projectDir,
		NonInteractive: hasFlag("--non-interactive") || hasFlag("-y"),
		DryRun:         hasFlag("--dry-run"),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runInit() {
	configDir := getConfigDir()
	scanner := bufio.NewScanner(os.Stdin)

	// Support: arc-sync init <url> [--token <token>]
	var url string
	inviteToken := getFlagValue(os.Args[2:], "--token")
	for _, arg := range os.Args[2:] {
		if !strings.HasPrefix(arg, "--") && arg != inviteToken {
			url = arg
			break
		}
	}

	if url == "" {
		fmt.Print("Arc Relay URL: ")
		if !scanner.Scan() {
			return
		}
		url = strings.TrimSpace(scanner.Text())
		if url == "" {
			fmt.Fprintln(os.Stderr, "Error: URL is required")
			os.Exit(1)
		}
	} else {
		fmt.Printf("Arc Relay URL: %s\n", url)
	}

	// Normalize URL
	url = strings.TrimRight(url, "/")

	var key string

	if inviteToken != "" {
		// Exchange invite token for API key (requires username + password)
		inviteUsername := getFlagValue(os.Args[2:], "--username")
		invitePassword := getFlagValue(os.Args[2:], "--password")
		key = tryInviteToken(url, inviteToken, inviteUsername, invitePassword)
		if key == "" {
			os.Exit(1)
		}
	} else {
		// Try device auth flow if the server supports it
		key = tryDeviceAuth(url)

		if key == "" {
			// Fall back to manual API key entry
			fmt.Print("API Key: ")
			if !scanner.Scan() {
				return
			}
			key = strings.TrimSpace(scanner.Text())
			if key == "" {
				fmt.Fprintln(os.Stderr, "Error: API key is required")
				os.Exit(1)
			}
		}
	}

	// Validate the credentials work
	fmt.Printf("Verifying connection...")
	client := relay.NewClient(url, key)
	_, err := client.ListServers()
	if err != nil {
		fmt.Printf(" failed\n")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Check your URL and API key and try again.")
		os.Exit(1)
	}
	fmt.Printf(" OK\n")

	cfg := &config.Config{
		RelayURL: url,
		APIKey:   key,
	}

	if err := config.SaveConfig(configDir, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	path := config.ConfigPath(configDir)
	fmt.Printf("\n✓  Config saved to %s (permissions: 600)\n\n", path)
	fmt.Println("   Your API key is stored in plaintext, protected by filesystem permissions.")
	fmt.Println("   This is the same approach used by gh, aws, and docker CLIs.")
	fmt.Println()
	fmt.Println("   To use environment variables instead (recommended for CI):")
	fmt.Printf("     export ARC_SYNC_URL=%q\n", url)
	fmt.Printf("     export ARC_SYNC_API_KEY=%q\n", key)
	fmt.Println()

	// Offer Claude Code integration
	offerClaudeIntegration(scanner)

	// Offer Codex CLI integration
	offerCodexIntegration(scanner)

	// Offer project-level setup if in a project directory
	offerProjectSetup(scanner)

	fmt.Println("Next steps:")
	fmt.Println("   cd <your-project> && arc-sync     # sync relay servers to your project")
}

// tryInviteToken exchanges an invite token for an API key.
// The user must choose a username and password to create their account.
// If username/password are provided as flags, those are used directly (non-interactive).
func tryInviteToken(baseURL, token, flagUsername, flagPassword string) string {
	scanner := bufio.NewScanner(os.Stdin)

	username := flagUsername
	password := flagPassword

	if username == "" {
		fmt.Print("Choose a username: ")
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "Error: username is required")
			return ""
		}
		username = strings.TrimSpace(scanner.Text())
		if username == "" {
			fmt.Fprintln(os.Stderr, "Error: username is required")
			return ""
		}
	} else {
		fmt.Printf("Username: %s\n", username)
	}

	if password == "" {
		fmt.Print("Choose a password (min 8 chars): ")
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "Error: password is required")
			return ""
		}
		password = strings.TrimSpace(scanner.Text())
	}

	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "Error: password must be at least 8 characters")
		return ""
	}

	fmt.Printf("Creating account...")

	tokenBody, _ := json.Marshal(map[string]string{
		"token":    token,
		"username": username,
		"password": password,
	})
	resp, err := http.Post(baseURL+"/api/auth/invite", "application/json", bytes.NewReader(tokenBody))
	if err != nil {
		fmt.Printf(" failed\n")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		APIKey string `json:"api_key"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf(" failed\n")
		return ""
	}

	if result.APIKey != "" {
		fmt.Printf(" OK\n")
		return result.APIKey
	}

	fmt.Printf(" failed\n")
	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "Server: %s\n", result.Error)
	}
	return ""
}

func runSetupClaude() {
	scanner := bufio.NewScanner(os.Stdin)
	offerClaudeIntegration(scanner)
}

func runSetupCodex() {
	scanner := bufio.NewScanner(os.Stdin)
	offerCodexIntegration(scanner)
}

// claudeInstructionsSnippet is appended to ~/.claude/CLAUDE.md to steer Claude
// toward using arc-sync for MCP server management instead of editing .mcp.json directly.
const claudeInstructionsSnippet = `
## MCP Server Management
MCP servers are managed by Arc Relay via arc-sync. Do not edit .mcp.json manually.
Use arc-sync commands: list, add <name>, remove <name>, server add/remove/start/stop.
Run "arc-sync list" to see available servers. Run "arc-sync" to sync new servers.
`

// claudeInstructionsMarker identifies the arc-sync section in CLAUDE.md.
const claudeInstructionsMarker = "## MCP Server Management"

// codexInstructionsSnippet is appended to ~/.codex/AGENTS.md to steer Codex
// toward using arc-sync for MCP server management instead of editing
// .codex/config.toml directly.
const codexInstructionsSnippet = `
## MCP Server Management
MCP servers are managed by Arc Relay via arc-sync. Do not edit .codex/config.toml or .mcp.json manually.
Use arc-sync commands: list, add <name>, remove <name>, server add/remove/start/stop.
Run "arc-sync list" to see available servers. Run "arc-sync" to sync new servers.
`

// codexInstructionsMarker identifies the arc-sync section in AGENTS.md.
const codexInstructionsMarker = "## MCP Server Management"

func offerClaudeIntegration(scanner *bufio.Scanner) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	claudeDir := filepath.Join(homeDir, ".claude")
	claudeMDPath := filepath.Join(claudeDir, "CLAUDE.md")
	skillDir := filepath.Join(claudeDir, "skills", "arc-sync")
	skillPath := filepath.Join(skillDir, "SKILL.md")

	// Check what's already installed
	hasInstructions := false
	hasSkill := false

	if data, err := os.ReadFile(claudeMDPath); err == nil { // #nosec G304 — homeDir + constant ".claude/CLAUDE.md"; integration-doc read, no credentials.
		hasInstructions = strings.Contains(string(data), claudeInstructionsMarker)
	}
	if _, err := os.Stat(skillPath); err == nil {
		hasSkill = true
	}

	if hasInstructions && hasSkill {
		fmt.Println("   Claude Code integration: already installed ✓")
		fmt.Println()
		return
	}

	fmt.Println("Claude Code integration:")
	fmt.Println("   Claude works better when it knows to use arc-sync for MCP servers")
	fmt.Println("   instead of editing .mcp.json directly. This installs:")
	if !hasInstructions {
		fmt.Println("     • ~/.claude/CLAUDE.md  — instructions for Claude to use arc-sync")
	}
	if !hasSkill {
		fmt.Println("     • ~/.claude/skills/arc-sync/SKILL.md  — the /arc-sync skill")
	}
	fmt.Println()
	fmt.Print("   Install Claude Code integration? [Y/n] ")

	if !scanner.Scan() {
		return
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Println("   Skipped. You can install manually later:")
		fmt.Println("     mkdir -p ~/.claude/skills/arc-sync")
		fmt.Println("     curl -fsSL https://raw.githubusercontent.com/comma-compliance/arc-relay/main/skills/arc-sync/SKILL.md \\")
		fmt.Println("       -o ~/.claude/skills/arc-sync/SKILL.md")
		fmt.Println()
		return
	}

	installed := 0

	// Install CLAUDE.md instructions
	if !hasInstructions {
		if err := os.MkdirAll(claudeDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "   Warning: could not create %s: %v\n", claudeDir, err)
		} else {
			f, err := os.OpenFile(claudeMDPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 — homeDir + constant ".claude/CLAUDE.md"; appends integration doc, no credentials.
			if err != nil {
				fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", claudeMDPath, err)
			} else {
				_, writeErr := f.WriteString(claudeInstructionsSnippet)
				closeErr := f.Close()
				if writeErr != nil {
					fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", claudeMDPath, writeErr)
				} else if closeErr != nil {
					fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", claudeMDPath, closeErr)
				} else {
					fmt.Printf("   ✓ Added MCP instructions to %s\n", claudeMDPath)
					installed++
				}
			}
		}
	}

	// Install skill
	if !hasSkill {
		if err := installSkillFromEmbed(skillDir, skillPath); err != nil {
			fmt.Fprintf(os.Stderr, "   Warning: could not install skill: %v\n", err)
			fmt.Println("   Install manually:")
			fmt.Println("     mkdir -p ~/.claude/skills/arc-sync")
			fmt.Println("     curl -fsSL https://raw.githubusercontent.com/comma-compliance/arc-relay/main/skills/arc-sync/SKILL.md \\")
			fmt.Println("       -o ~/.claude/skills/arc-sync/SKILL.md")
		} else {
			fmt.Printf("   ✓ Installed skill to %s\n", skillPath)
			installed++
		}
	}

	if installed > 0 {
		fmt.Println()
	}
}

func offerCodexIntegration(scanner *bufio.Scanner) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	codexDir := filepath.Join(homeDir, ".codex")
	agentsPath := filepath.Join(codexDir, "AGENTS.md")

	if hasMarker(agentsPath, codexInstructionsMarker) {
		fmt.Println("   Codex CLI integration: already installed ✓")
		fmt.Println()
		return
	}

	fmt.Println("Codex CLI integration:")
	fmt.Println("   Codex works better when it knows to use arc-sync for MCP servers")
	fmt.Println("   instead of editing .codex/config.toml directly. This installs:")
	fmt.Println("     • ~/.codex/AGENTS.md  — instructions for Codex to use arc-sync")
	fmt.Println()
	fmt.Print("   Install Codex CLI integration? [Y/n] ")

	if !scanner.Scan() {
		return
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Println("   Skipped. You can install manually later in ~/.codex/AGENTS.md.")
		fmt.Println()
		return
	}

	if err := os.MkdirAll(codexDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "   Warning: could not create %s: %v\n", codexDir, err)
		fmt.Println()
		return
	}

	if err := appendSnippetIfMissing(agentsPath, codexInstructionsMarker, codexInstructionsSnippet); err != nil {
		fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", agentsPath, err)
		fmt.Println()
		return
	}

	fmt.Printf("   ✓ Added MCP instructions to %s\n", agentsPath)
	fmt.Println()
}

// projectClaudeSnippet is the content added to a project's .claude/CLAUDE.md.
const projectClaudeSnippet = `## MCP Servers
This project uses Arc Relay for shared tool access.
- If arc-sync is not installed, run: arc-sync init (or ask your admin for an install command)
- Use the arc-sync skill for all server management (adding, removing, listing)
- Do NOT edit .mcp.json manually - use arc-sync commands instead
- Run "arc-sync list" to see available servers, "arc-sync" to sync
`

const projectClaudeMarker = "## MCP Servers"

// projectCodexSnippet is the content added to a project's AGENTS.md.
const projectCodexSnippet = `## MCP Servers
This project uses Arc Relay for shared tool access.
- If arc-sync is not installed, run: arc-sync init (or ask your admin for an install command)
- Use arc-sync for all server management (adding, removing, listing)
- Do NOT edit .codex/config.toml or .mcp.json manually - use arc-sync commands instead
- Run "arc-sync list" to see available servers, "arc-sync" to sync
`

const projectCodexMarker = "## MCP Servers"

func runSetupProject() {
	projectDir := getProjectDir()
	installedClaude := installProjectClaude(projectDir)
	installedCodex := installProjectCodex(projectDir)
	if installedClaude || installedCodex {
		fmt.Println()
		fmt.Println("Commit project instruction files so teammates get guided setup automatically.")
	}
}

// offerProjectSetup prompts the user to set up project-level tool instructions.
func offerProjectSetup(scanner *bufio.Scanner) {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	projectDir, err := project.DetectProjectDir(cwd)
	if err != nil {
		return
	}

	hasClaude := hasProjectClaude(projectDir)
	hasCodex := hasProjectCodex(projectDir)
	if hasClaude && hasCodex {
		return
	}

	// Check if this looks like a git project (worth sharing)
	if _, err := os.Stat(filepath.Join(projectDir, ".git")); err != nil {
		return // not a git repo, skip the offer
	}

	fmt.Println("Project setup:")
	fmt.Println("   Add MCP instructions to this project so teammates get guided setup")
	fmt.Println("   when they open it with Claude Code and Codex CLI.")
	if !hasClaude {
		fmt.Println("     • .claude/CLAUDE.md")
	}
	if !hasCodex {
		fmt.Println("     • AGENTS.md")
	}
	fmt.Print("   Set up project for team sharing? [Y/n] ")

	if !scanner.Scan() {
		return
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Println("   Skipped. Run 'arc-sync setup-project' later to set up.")
		fmt.Println()
		return
	}

	installProjectClaude(projectDir)
	installProjectCodex(projectDir)
	fmt.Println()
}

// installProjectClaude adds MCP instructions to the project's .claude/CLAUDE.md.
func installProjectClaude(projectDir string) bool {
	claudeDir := filepath.Join(projectDir, ".claude")
	claudePath := filepath.Join(claudeDir, "CLAUDE.md")

	// Check if already present
	if hasMarker(claudePath, projectClaudeMarker) {
		fmt.Printf("   Project CLAUDE.md: already has MCP instructions ✓\n")
		return false
	}

	if err := os.MkdirAll(claudeDir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "   Warning: could not create %s: %v\n", claudeDir, err)
		return false
	}

	f, err := os.OpenFile(claudePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G302 G304 - projectDir + constant ".claude/CLAUDE.md"; appends integration doc, no credentials. git will set perms
	if err != nil {
		fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", claudePath, err)
		return false
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString("\n" + projectClaudeSnippet); err != nil {
		fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", claudePath, err)
		return false
	}

	fmt.Printf("   ✓ Added MCP instructions to %s\n", claudePath)
	return true
}

// installProjectCodex adds MCP instructions to the project's AGENTS.md.
func installProjectCodex(projectDir string) bool {
	agentsPath := filepath.Join(projectDir, "AGENTS.md")

	if hasMarker(agentsPath, projectCodexMarker) {
		fmt.Printf("   Project AGENTS.md: already has MCP instructions ✓\n")
		return false
	}

	snippet := projectCodexSnippet
	if data, err := os.ReadFile(agentsPath); err == nil && len(data) > 0 { // #nosec G304 — projectDir + constant "AGENTS.md"; integration-doc read, no credentials.
		snippet = "\n" + snippet
	}

	if err := appendSnippetIfMissing(agentsPath, projectCodexMarker, snippet); err != nil {
		fmt.Fprintf(os.Stderr, "   Warning: could not write %s: %v\n", agentsPath, err)
		return false
	}

	fmt.Printf("   ✓ Added MCP instructions to %s\n", agentsPath)
	return true
}

// hasProjectClaude checks if the project already has MCP instructions in .claude/CLAUDE.md.
func hasProjectClaude(projectDir string) bool {
	claudePath := filepath.Join(projectDir, ".claude", "CLAUDE.md")
	return hasMarker(claudePath, projectClaudeMarker)
}

// hasProjectCodex checks if the project already has MCP instructions in AGENTS.md.
func hasProjectCodex(projectDir string) bool {
	agentsPath := filepath.Join(projectDir, "AGENTS.md")
	return hasMarker(agentsPath, projectCodexMarker)
}

func installSkillFromEmbed(skillDir, skillPath string) error {
	if err := os.MkdirAll(skillDir, 0750); err != nil {
		return fmt.Errorf("creating skill directory: %w", err)
	}

	if err := os.WriteFile(skillPath, embeddedSkillMD, 0600); err != nil { // #nosec G304 — homeDir + constant "skills/arc-sync/SKILL.md"; writes embedded skill doc, no credentials.
		return fmt.Errorf("writing skill: %w", err)
	}

	return nil
}

func hasMarker(path, marker string) bool {
	// path is always built by callers as homeDir/projectDir + a constant
	// integration-doc name (CLAUDE.md / AGENTS.md); read-only marker check.
	data, err := os.ReadFile(path) // #nosec G304 — caller-constructed homeDir/projectDir + constant doc name; read-only marker check.
	if err != nil {
		return false
	}
	return strings.Contains(string(data), marker)
}

func appendSnippetIfMissing(path, marker, snippet string) error {
	if hasMarker(path, marker) {
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 — caller-constructed homeDir/projectDir + constant doc name; appends integration doc, no credentials.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(snippet); err != nil {
		return err
	}

	return nil
}

func detectedTargets(projectDir string) []project.Target {
	return project.DetectedTargetsOrDefault(projectDir)
}

func configuredServers(projectDir, relayURL string, targets []project.Target) ([]project.ManagedServer, error) {
	return project.ReadManagedServersFromTargets(projectDir, relayURL, targets)
}

func runList() {
	configDir := getConfigDir()
	projectDir := getProjectDir()
	jsonOutput := hasFlag("--json")

	creds, err := config.ResolveCredentials(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := relay.NewClient(creds.RelayURL, creds.APIKey)
	servers, err := client.ListServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	targets := detectedTargets(projectDir)
	configured, err := configuredServers(projectDir, creds.RelayURL, targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading project config: %v\n", err)
		os.Exit(1)
	}

	configuredNames := make(map[string]bool)
	for _, s := range configured {
		configuredNames[s.Name] = true
	}

	state, _ := config.LoadState(configDir)

	if jsonOutput {
		type serverInfo struct {
			Name          string `json:"name"`
			DisplayName   string `json:"display_name"`
			Status        string `json:"status"`
			Health        string `json:"health,omitempty"`
			HealthCheckAt string `json:"health_check_at,omitempty"`
			HealthError   string `json:"health_error,omitempty"`
			Configured    bool   `json:"configured"`
			Skipped       bool   `json:"skipped"`
		}
		var info []serverInfo
		for _, s := range servers {
			info = append(info, serverInfo{
				Name:          s.Name,
				DisplayName:   s.DisplayName,
				Status:        s.Status,
				Health:        s.Health,
				HealthCheckAt: s.HealthCheckAt,
				HealthError:   s.HealthError,
				Configured:    configuredNames[s.Name],
				Skipped:       state.IsSkipped(projectDir, s.Name),
			})
		}
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Arc Relay: %s\n", creds.RelayURL)
	fmt.Printf("Project:      %s\n\n", projectDir)

	if len(servers) == 0 {
		fmt.Println("No servers found.")
		return
	}

	fmt.Printf("%-25s %-10s %-12s %-12s %s\n", "NAME", "STATUS", "HEALTH", "CONFIGURED", "SKIPPED")
	fmt.Println(strings.Repeat("-", 75))
	for _, s := range servers {
		configured := "no"
		if configuredNames[s.Name] {
			configured = "yes"
		}
		skipped := ""
		if state.IsSkipped(projectDir, s.Name) {
			skipped = "yes"
		}
		health := healthDisplay(s)
		fmt.Printf("%-25s %-10s %-12s %-12s %s\n", s.Name, s.Status, health, configured, skipped)
	}
}

func runAdd() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: arc-sync add <server-name>")
		os.Exit(1)
	}
	serverName := os.Args[2]

	configDir := getConfigDir()
	projectDir := getProjectDir()

	creds, err := config.ResolveCredentials(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := relay.NewClient(creds.RelayURL, creds.APIKey)
	servers, err := client.ListRunningServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var found *relay.Server
	for i := range servers {
		if servers[i].Name == serverName {
			found = &servers[i]
			break
		}
	}

	if found == nil {
		fmt.Fprintf(os.Stderr, "Error: server %q not found or not running\n", serverName)
		fmt.Fprintln(os.Stderr, "Run 'arc-sync list' to see available servers")
		os.Exit(1)
	}

	// Warn if server is unhealthy
	if found.Health == "unhealthy" {
		errMsg := found.HealthError
		if errMsg == "" {
			errMsg = "unknown error"
		}
		if !hasFlag("--non-interactive") && !hasFlag("-y") {
			fmt.Fprintf(os.Stderr, "Warning: %s is running but health check failed: %s\n", serverName, errMsg)
			fmt.Fprint(os.Stderr, "Add anyway? [y/n] ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() || strings.TrimSpace(strings.ToLower(scanner.Text())) != "y" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				os.Exit(0)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: %s is running but health check failed: %s\n", serverName, errMsg)
		}
	}

	targets := detectedTargets(projectDir)
	toAdd := []project.ManagedServer{
		{Name: serverName, URL: client.ServerProxyURL(serverName)},
	}

	if hasFlag("--dry-run") {
		for _, target := range targets {
			fmt.Printf("DRY RUN — would add %s to %s\n", serverName, filepath.Join(projectDir, target.ConfigFileName()))
		}
		return
	}

	// Show gitignore warnings.
	for _, target := range targets {
		warnings := safety.CheckGitignore(projectDir, target.ConfigFileName())
		fmt.Print(safety.FormatWarnings(warnings))
	}

	for _, target := range targets {
		if err := target.Write(projectDir, creds.RelayURL, creds.APIKey, toAdd); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s config: %v\n", target.Name(), err)
			os.Exit(1)
		}
	}

	fmt.Printf("✓  Added %s to %d target(s)\n", serverName, len(targets))

	// One-time hint about project setup
	if !hasProjectClaude(projectDir) || !hasProjectCodex(projectDir) {
		if _, err := os.Stat(filepath.Join(projectDir, ".git")); err == nil {
			fmt.Println()
			fmt.Println("   Tip: Run 'arc-sync setup-project' to add Claude Code and Codex")
			fmt.Println("   instructions to this repo so teammates get guided setup automatically.")
		}
	}
}

func runRemove() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: arc-sync remove <server-name>")
		os.Exit(1)
	}
	serverName := os.Args[2]

	projectDir := getProjectDir()
	configDir := getConfigDir()

	targets := detectedTargets(projectDir)

	if hasFlag("--dry-run") {
		for _, target := range targets {
			fmt.Printf("DRY RUN — would remove %s from %s\n", serverName, filepath.Join(projectDir, target.ConfigFileName()))
		}
		return
	}

	removedTargets := 0
	for _, target := range targets {
		removed, err := target.Remove(projectDir, []string{serverName})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error removing from %s config: %v\n", target.Name(), err)
			os.Exit(1)
		}
		if len(removed) > 0 {
			removedTargets++
		}
	}

	if removedTargets == 0 {
		fmt.Fprintf(os.Stderr, "Server %q not found in detected project targets\n", serverName)
		os.Exit(1)
	}

	// Also add to skip list so it won't be prompted again
	state, _ := config.LoadState(configDir)
	state.AddSkipped(projectDir, serverName)
	if err := config.SaveState(configDir, state); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removed from project config but failed to update skip list: %v\n", err)
	}

	fmt.Printf("✓  Removed %s from %d target(s) (skipped for future syncs)\n", serverName, removedTargets)
	fmt.Printf("   To re-add later: arc-sync reset && arc-sync add %s\n", serverName)
}

func runReset() {
	configDir := getConfigDir()
	projectDir := getProjectDir()

	state, err := config.LoadState(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	skipped := state.GetSkipped(projectDir)
	if len(skipped) == 0 {
		fmt.Println("No skipped servers for this project.")
		return
	}

	state.ClearSkipped(projectDir)
	if err := config.SaveState(configDir, state); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓  Cleared skip list for %s\n", projectDir)
	fmt.Printf("   Previously skipped: %s\n", strings.Join(skipped, ", "))
}

func runStatus() {
	configDir := getConfigDir()
	projectDir := getProjectDir()
	jsonOutput := hasFlag("--json")

	creds, err := config.ResolveCredentials(configDir)

	if jsonOutput {
		type serverHealth struct {
			Name          string `json:"name"`
			Status        string `json:"status"`
			Health        string `json:"health,omitempty"`
			HealthCheckAt string `json:"health_check_at,omitempty"`
			HealthError   string `json:"health_error,omitempty"`
		}
		type targetStatus struct {
			Name        string `json:"name"`
			ConfigFile  string `json:"config_file"`
			Detected    bool   `json:"detected"`
			ServerCount int    `json:"server_count"`
		}
		type integrationStatus struct {
			GlobalClaude  bool `json:"global_claude"`
			GlobalCodex   bool `json:"global_codex"`
			ProjectClaude bool `json:"project_claude"`
			ProjectCodex  bool `json:"project_codex"`
		}
		type statusInfo struct {
			RelayURL        string            `json:"relay_url,omitempty"`
			AuthSource      string            `json:"auth_source,omitempty"`
			ProjectDir      string            `json:"project_dir"`
			ConfigDir       string            `json:"config_dir"`
			HasConfig       bool              `json:"has_config"`
			Error           string            `json:"error,omitempty"`
			ConfiguredCount int               `json:"configured_count"`
			SkippedCount    int               `json:"skipped_count"`
			Targets         []targetStatus    `json:"targets,omitempty"`
			Integrations    integrationStatus `json:"integrations"`
			Servers         []serverHealth    `json:"servers,omitempty"`
		}
		info := statusInfo{
			ProjectDir: projectDir,
			ConfigDir:  configDir,
			HasConfig:  err == nil,
			Integrations: integrationStatus{
				ProjectClaude: hasProjectClaude(projectDir),
				ProjectCodex:  hasProjectCodex(projectDir),
			},
		}
		homeDir, _ := os.UserHomeDir()
		if homeDir != "" {
			skillPath := filepath.Join(homeDir, ".claude", "skills", "arc-sync", "SKILL.md")
			if _, statErr := os.Stat(skillPath); statErr == nil {
				info.Integrations.GlobalClaude = true
			}
			claudeMDPath := filepath.Join(homeDir, ".claude", "CLAUDE.md")
			if hasMarker(claudeMDPath, claudeInstructionsMarker) {
				info.Integrations.GlobalClaude = true
			}
			agentsPath := filepath.Join(homeDir, ".codex", "AGENTS.md")
			info.Integrations.GlobalCodex = hasMarker(agentsPath, codexInstructionsMarker)
		}
		if err != nil {
			info.Error = err.Error()
		} else {
			info.RelayURL = creds.RelayURL
			info.AuthSource = creds.Source

			targets := detectedTargets(projectDir)
			configured, _ := configuredServers(projectDir, creds.RelayURL, targets)
			info.ConfiguredCount = len(configured)

			state, _ := config.LoadState(configDir)
			info.SkippedCount = len(state.GetSkipped(projectDir))

			for _, t := range project.AllTargets() {
				detected := t.Detect(projectDir)
				serverCount := 0
				if detected {
					managed, _ := t.Read(projectDir, creds.RelayURL)
					serverCount = len(managed)
				}
				info.Targets = append(info.Targets, targetStatus{
					Name:        t.Name(),
					ConfigFile:  t.ConfigFileName(),
					Detected:    detected,
					ServerCount: serverCount,
				})
			}

			client := relay.NewClient(creds.RelayURL, creds.APIKey)
			if allServers, srvErr := client.ListServers(); srvErr == nil {
				for _, s := range allServers {
					info.Servers = append(info.Servers, serverHealth{
						Name:          s.Name,
						Status:        s.Status,
						Health:        s.Health,
						HealthCheckAt: s.HealthCheckAt,
						HealthError:   s.HealthError,
					})
				}
			}
		}
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))
		return
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Relay:     not configured (%v)\n", err)
		fmt.Fprintf(os.Stderr, "Config:       %s\n", config.ConfigPath(configDir))
		fmt.Fprintf(os.Stderr, "\nRun 'arc-sync init' to set up.\n")
		os.Exit(1)
	}

	fmt.Printf("Relay:     %s\n", creds.RelayURL)
	fmt.Printf("Auth:         %s\n", creds.Source)
	fmt.Printf("Config:       %s\n", config.ConfigPath(configDir))
	fmt.Printf("State:        %s\n\n", config.StatePath(configDir))

	// Check config permissions
	if warning := config.CheckPermissions(configDir); warning != "" {
		fmt.Println(warning)
		fmt.Println()
	}

	fmt.Printf("Project:      %s\n", projectDir)

	// Show detected targets
	allTargets := project.AllTargets()
	fmt.Println("Targets detected:")
	for _, t := range allTargets {
		if t.Detect(projectDir) {
			configured, _ := t.Read(projectDir, creds.RelayURL)
			fmt.Printf("  ✓ %-12s %-25s (%d relay server(s) configured)\n",
				t.Name(), t.ConfigFileName(), len(configured))
		} else {
			fmt.Printf("  ✗ %-12s %-25s (not found)\n", t.Name(), t.ConfigFileName())
		}
	}

	// Security section
	fmt.Println("\nSecurity:")
	for _, t := range allTargets {
		if t.Detect(projectDir) {
			warnings := safety.CheckGitignore(projectDir, t.ConfigFileName())
			fmt.Print(safety.FormatWarnings(warnings))
		}
	}

	configScope := safety.ClassifyPath(config.ConfigPath(configDir), projectDir)
	if configScope == safety.ScopeUser {
		fmt.Println("  ✓  Config directory is outside project (not committed)")
	}

	// Claude integration health
	fmt.Println("\nClaude Integration:")
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		// Global skill
		skillPath := filepath.Join(homeDir, ".claude", "skills", "arc-sync", "SKILL.md")
		if _, err := os.Stat(skillPath); err == nil {
			fmt.Println("  ✓  Global skill:      installed")
		} else {
			fmt.Println("  ✗  Global skill:      not found  (run: arc-sync setup-claude)")
		}

		// Global CLAUDE.md
		claudeMDPath := filepath.Join(homeDir, ".claude", "CLAUDE.md")
		claudeData, claudeErr := os.ReadFile(claudeMDPath) // #nosec G304 - homeDir + constant ".claude/CLAUDE.md"; status read of integration doc.
		if claudeErr == nil && strings.Contains(string(claudeData), claudeInstructionsMarker) {
			fmt.Println("  ✓  Global CLAUDE.md:  installed")
		} else {
			fmt.Println("  ✗  Global CLAUDE.md:  not found  (run: arc-sync setup-claude)")
		}
	}

	// Project CLAUDE.md
	if hasProjectClaude(projectDir) {
		fmt.Println("  ✓  Project CLAUDE.md: installed")
	} else {
		fmt.Println("  ✗  Project CLAUDE.md: not found  (run: arc-sync setup-project)")
	}

	fmt.Println("\nCodex Integration:")
	if homeDir != "" {
		agentsPath := filepath.Join(homeDir, ".codex", "AGENTS.md")
		if hasMarker(agentsPath, codexInstructionsMarker) {
			fmt.Println("  ✓  Global AGENTS.md:  installed")
		} else {
			fmt.Println("  ✗  Global AGENTS.md:  not found  (run: arc-sync setup-codex)")
		}
	}

	if hasProjectCodex(projectDir) {
		fmt.Println("  ✓  Project AGENTS.md: installed")
	} else {
		fmt.Println("  ✗  Project AGENTS.md: not found  (run: arc-sync setup-project)")
	}

	// Show skipped
	state, _ := config.LoadState(configDir)
	skipped := state.GetSkipped(projectDir)
	if len(skipped) > 0 {
		fmt.Printf("\nSkipped servers: %s\n", strings.Join(skipped, ", "))
	}
}

// healthDisplay returns a short display string for a server's health status.
func healthDisplay(s relay.Server) string {
	if s.Health == "" {
		return "-"
	}
	return s.Health
}

// tryDeviceAuth attempts the device authorization flow with the relay.
// Returns the API key if successful, or empty string to fall back to manual entry.
// The device auth flow works like GitHub CLI's "gh auth login":
//  1. POST /api/auth/device — get a device code and user URL
//  2. User opens the URL in their browser and approves
//  3. Poll POST /api/auth/device/token until approved
func tryDeviceAuth(baseURL string) string {
	// Check if the server supports device auth
	checkURL := baseURL + "/api/auth/device"
	resp, err := http.Post(checkURL, "application/json", strings.NewReader("{}")) //nolint:gosec // #nosec G107 -- baseURL is operator-configured server URL, not user input
	if err != nil {
		return "" // Server not reachable or doesn't support device auth
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return "" // Endpoint not available, fall back to manual
	}

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var deviceResp struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &deviceResp); err != nil || deviceResp.DeviceCode == "" {
		return ""
	}

	fmt.Println()
	fmt.Printf("  Open this URL in your browser to authorize:\n")
	fmt.Printf("  %s\n\n", deviceResp.VerificationURL)
	fmt.Printf("  Your code: %s\n\n", deviceResp.UserCode)
	fmt.Printf("  Waiting for authorization...")

	// Poll for token
	interval := deviceResp.Interval
	if interval < 5 {
		interval = 5
	}
	tokenURL := baseURL + "/api/auth/device/token"

	for i := 0; i < 60; i++ {
		time.Sleep(time.Duration(interval) * time.Second)

		tokenBody, _ := json.Marshal(map[string]string{"device_code": deviceResp.DeviceCode})
		tokenResp, err := http.Post(tokenURL, "application/json", bytes.NewReader(tokenBody)) //nolint:gosec // #nosec G107 -- baseURL is operator-configured server URL, not user input
		if err != nil {
			continue
		}

		var tokenResult struct {
			APIKey string `json:"api_key"`
			Error  string `json:"error"`
		}
		respBody, readErr := io.ReadAll(tokenResp.Body)
		_ = tokenResp.Body.Close()
		if readErr != nil {
			continue
		}
		if err := json.Unmarshal(respBody, &tokenResult); err != nil {
			continue
		}

		if tokenResult.APIKey != "" {
			fmt.Printf(" authorized!\n\n")
			return tokenResult.APIKey
		}

		if tokenResult.Error == "authorization_pending" {
			fmt.Printf(".")
			continue
		}

		if tokenResult.Error == "expired_token" || tokenResult.Error == "access_denied" {
			fmt.Printf(" %s\n", tokenResult.Error)
			return ""
		}
	}

	fmt.Printf(" timed out\n")
	return ""
}

// --- Server management subcommands ---

func printServerUsage() {
	fmt.Println(`Usage: arc-sync server <command> [options]

Manage MCP servers on the relay instance itself.
Requires your API key to have write/admin access.

Commands:
  add       Create a new server on the relay
  remove    Delete a server from the relay
  start     Start a server
  stop      Stop a server

Add syntax (mirrors 'claude mcp add'):
  arc-sync server add <name> --type remote <url>
  arc-sync server add <name> --type remote <url> --auth bearer --token <token>
  arc-sync server add <name> --type remote <url> --auth api-key --header-name X-API-Key --token <key>
  arc-sync server add <name> --type stdio --image <docker-image> [-- <command> [args...]]
  arc-sync server add <name> --type stdio --build python --package <pip-package>
  arc-sync server add <name> --type stdio --build node --package <npm-package>
  arc-sync server add <name> --type http --image <docker-image> --port <port>
  arc-sync server add <name> --type http --url <external-url>

Options for add:
  --display-name <name>    Human-readable display name (defaults to server name)
  --env KEY=VALUE          Environment variable (can be repeated)
  --start                  Start the server immediately after creating it

Other commands:
  arc-sync server remove <name-or-id>
  arc-sync server start <name-or-id>
  arc-sync server stop <name-or-id>`)
}

func runServer() {
	if len(os.Args) < 3 {
		printServerUsage()
		return
	}

	switch os.Args[2] {
	case "add":
		runServerAdd()
	case "remove", "rm", "delete":
		runServerRemove()
	case "start":
		runServerStartStop("start")
	case "stop":
		runServerStartStop("stop")
	case "--help", "help", "-h":
		printServerUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown server command: %s\n\n", os.Args[2])
		printServerUsage()
		os.Exit(1)
	}
}

func runServerAdd() {
	// Parse args after "server add"
	args := os.Args[3:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: arc-sync server add <name> --type <type> [options]")
		os.Exit(1)
	}

	name := args[0]
	args = args[1:]

	// Parse flags from remaining args
	serverType := getFlagValue(args, "--type")
	displayName := getFlagValue(args, "--display-name")
	if displayName == "" {
		displayName = name
	}

	if serverType == "" {
		fmt.Fprintln(os.Stderr, "Error: --type is required (remote, stdio, or http)")
		os.Exit(1)
	}

	configDir := getConfigDir()
	creds, err := config.ResolveCredentials(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := relay.NewClient(creds.RelayURL, creds.APIKey)

	var cfgJSON []byte

	switch serverType {
	case "remote":
		cfgJSON, err = buildRemoteConfig(args)
	case "stdio":
		cfgJSON, err = buildStdioConfig(args)
	case "http":
		cfgJSON, err = buildHTTPConfig(args)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown server type %q (use remote, stdio, or http)\n", serverType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	req := &relay.CreateServerRequest{
		Name:        name,
		DisplayName: displayName,
		ServerType:  serverType,
		Config:      cfgJSON,
	}

	if hasFlagInArgs(args, "--dry-run") {
		data, _ := json.MarshalIndent(req, "", "  ")
		fmt.Printf("DRY RUN — would create server on %s:\n%s\n", creds.RelayURL, string(data))
		return
	}

	fmt.Printf("Creating server %q on %s...\n", name, creds.RelayURL)
	detail, err := client.CreateServer(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓  Server created: %s (id: %s, status: %s)\n", detail.Name, detail.ID, detail.Status)

	// Optionally start
	if hasFlagInArgs(args, "--start") {
		fmt.Printf("Starting %s...\n", name)
		if err := client.StartServer(detail.ID); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: server created but failed to start: %v\n", err)
		} else {
			fmt.Printf("✓  Server started\n")
		}
	}

	fmt.Printf("\nTo sync this server to your project: arc-sync add %s\n", name)
}

func buildRemoteConfig(args []string) ([]byte, error) {
	// The URL is the first positional arg (after flags are consumed)
	url := getPositionalArg(args)
	if url == "" {
		url = getFlagValue(args, "--url")
	}
	if url == "" {
		return nil, fmt.Errorf("URL is required for remote servers")
	}

	authType := getFlagValue(args, "--auth")
	if authType == "" {
		authType = "none"
	}

	auth := relay.RemoteAuth{Type: authType}

	switch authType {
	case "bearer":
		auth.Token = getFlagValue(args, "--token")
		if auth.Token == "" {
			return nil, fmt.Errorf("--token is required for bearer auth")
		}
	case "api-key", "api_key":
		auth.Type = "api_key"
		auth.Token = getFlagValue(args, "--token")
		auth.HeaderName = getFlagValue(args, "--header-name")
		if auth.Token == "" {
			return nil, fmt.Errorf("--token is required for api-key auth")
		}
		if auth.HeaderName == "" {
			auth.HeaderName = "X-API-Key"
		}
	case "none":
		// no-op
	default:
		return nil, fmt.Errorf("unknown auth type %q (use none, bearer, or api-key)", authType)
	}

	cfg := relay.RemoteConfig{URL: url, Auth: auth}
	return json.Marshal(cfg)
}

func buildStdioConfig(args []string) ([]byte, error) {
	cfg := relay.StdioConfig{
		Env: parseEnvFlags(args),
	}

	// Check for --build mode
	buildRuntime := getFlagValue(args, "--build")
	if buildRuntime != "" {
		pkg := getFlagValue(args, "--package")
		if pkg == "" {
			return nil, fmt.Errorf("--package is required with --build")
		}
		if buildRuntime != "python" && buildRuntime != "node" {
			return nil, fmt.Errorf("--build runtime must be python or node, got %q", buildRuntime)
		}
		cfg.Build = &relay.StdioBuildConfig{
			Runtime: buildRuntime,
			Package: pkg,
			Version: getFlagValue(args, "--version"),
		}
		gitURL := getFlagValue(args, "--git-url")
		if gitURL != "" {
			cfg.Build.GitURL = gitURL
		}
		return json.Marshal(cfg)
	}

	// Image mode
	cfg.Image = getFlagValue(args, "--image")
	if cfg.Image == "" {
		return nil, fmt.Errorf("either --image or --build is required for stdio servers")
	}

	// Check for command after --
	if cmd := getCommandAfterDash(args); len(cmd) > 0 {
		cfg.Command = cmd
	}

	entrypoint := getFlagValue(args, "--entrypoint")
	if entrypoint != "" {
		cfg.Entrypoint = strings.Fields(entrypoint)
	}

	return json.Marshal(cfg)
}

func buildHTTPConfig(args []string) ([]byte, error) {
	cfg := relay.HTTPConfig{
		Env: parseEnvFlags(args),
	}

	cfg.Image = getFlagValue(args, "--image")
	cfg.URL = getFlagValue(args, "--url")
	if cfg.URL == "" {
		cfg.URL = getPositionalArg(args)
	}

	if cfg.Image == "" && cfg.URL == "" {
		return nil, fmt.Errorf("either --image or --url is required for http servers")
	}

	portStr := getFlagValue(args, "--port")
	if portStr != "" {
		if _, err := fmt.Sscanf(portStr, "%d", &cfg.Port); err != nil {
			return nil, fmt.Errorf("invalid --port value %q: %w", portStr, err)
		}
	}

	cfg.HealthCheck = getFlagValue(args, "--health-check")

	return json.Marshal(cfg)
}

func runServerRemove() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: arc-sync server remove <name-or-id>")
		os.Exit(1)
	}
	nameOrID := os.Args[3]

	configDir := getConfigDir()
	creds, err := config.ResolveCredentials(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := relay.NewClient(creds.RelayURL, creds.APIKey)

	// Try to find the server by name first
	serverID := nameOrID
	servers, err := client.ListServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	for _, s := range servers {
		if s.Name == nameOrID {
			serverID = s.ID
			break
		}
	}

	fmt.Printf("Removing server %q from %s...\n", nameOrID, creds.RelayURL)
	if err := client.DeleteServer(serverID); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓  Server removed\n")
}

func runServerStartStop(action string) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: arc-sync server %s <name-or-id>\n", action)
		os.Exit(1)
	}
	nameOrID := os.Args[3]

	configDir := getConfigDir()
	creds, err := config.ResolveCredentials(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := relay.NewClient(creds.RelayURL, creds.APIKey)

	// Resolve name to ID
	serverID := nameOrID
	servers, err := client.ListServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	for _, s := range servers {
		if s.Name == nameOrID {
			serverID = s.ID
			break
		}
	}

	var actionErr error
	switch action {
	case "start":
		fmt.Printf("Starting %s...\n", nameOrID)
		actionErr = client.StartServer(serverID)
	case "stop":
		fmt.Printf("Stopping %s...\n", nameOrID)
		actionErr = client.StopServer(serverID)
	}

	if actionErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", actionErr)
		os.Exit(1)
	}

	fmt.Printf("✓  Server %sed\n", action)
}

// --- Flag parsing helpers for server subcommands ---

func getFlagValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasFlagInArgs(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}

// getPositionalArg returns the first arg that isn't a flag or a flag value.
func getPositionalArg(args []string) string {
	skipNext := false
	knownFlags := map[string]bool{
		"--type": true, "--display-name": true, "--auth": true, "--token": true,
		"--username": true, "--password": true,
		"--header-name": true, "--image": true, "--build": true, "--package": true,
		"--version": true, "--git-url": true, "--entrypoint": true, "--url": true,
		"--port": true, "--health-check": true, "--env": true, "--config": true,
		"--project": true,
	}
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if knownFlags[arg] {
			skipNext = true
			continue
		}
		if arg == "--" || arg == "--dry-run" || arg == "--start" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			continue
		}
		return arg
	}
	return ""
}

// getCommandAfterDash returns everything after a bare "--" in the args.
func getCommandAfterDash(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return nil
}

// parseEnvFlags collects all --env KEY=VALUE pairs from args.
func parseEnvFlags(args []string) map[string]string {
	env := make(map[string]string)
	for i, arg := range args {
		if arg == "--env" && i+1 < len(args) {
			kv := args[i+1]
			if k, v, ok := strings.Cut(kv, "="); ok {
				env[k] = v
			}
		}
	}
	if len(env) == 0 {
		return nil
	}
	return env
}
