package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize vulnex configuration for a project",
	Long: `Scan the current directory for lockfiles and CI configuration,
then create default vulnex configuration files.

Creates .vulnex-policy.yaml and .vulnexignore if they don't exist.`,
	Args: cobra.NoArgs,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Initializing vulnex in %s\n\n", cwd)

	// Detect lockfiles
	lockfiles := detectLockfiles(cwd)
	if len(lockfiles) > 0 {
		fmt.Fprintf(os.Stderr, "Detected project files:\n")
		for _, lf := range lockfiles {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", lf.file, lf.ecosystem)
		}
	} else {
		fmt.Fprintf(os.Stderr, "No lockfiles detected\n")
	}
	fmt.Fprintln(os.Stderr)

	// Detect CI
	ci := detectCI(cwd)
	if ci != "" {
		fmt.Fprintf(os.Stderr, "Detected CI: %s\n", ci)
		printCISnippet(ci)
		fmt.Fprintln(os.Stderr)
	}

	// Create .vulnex-policy.yaml
	policyPath := filepath.Join(cwd, ".vulnex-policy.yaml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		if err := os.WriteFile(policyPath, []byte(defaultPolicy), 0644); err != nil {
			return fmt.Errorf("creating policy file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Created %s\n", ".vulnex-policy.yaml")
	} else {
		fmt.Fprintf(os.Stderr, "Skipped %s (already exists)\n", ".vulnex-policy.yaml")
	}

	// Create .vulnexignore
	ignorePath := filepath.Join(cwd, ".vulnexignore")
	if _, err := os.Stat(ignorePath); os.IsNotExist(err) {
		if err := os.WriteFile(ignorePath, []byte(defaultIgnore), 0644); err != nil {
			return fmt.Errorf("creating ignore file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Created %s\n", ".vulnexignore")
	} else {
		fmt.Fprintf(os.Stderr, "Skipped %s (already exists)\n", ".vulnexignore")
	}

	fmt.Fprintf(os.Stderr, "\nDone! Run 'vulnex scan <lockfile>' to scan for vulnerabilities.\n")
	return nil
}

type lockfileInfo struct {
	file      string
	ecosystem string
}

func detectLockfiles(dir string) []lockfileInfo {
	known := []struct {
		filename  string
		ecosystem string
	}{
		{"go.sum", "Go"},
		{"package-lock.json", "npm"},
		{"yarn.lock", "npm"},
		{"pnpm-lock.yaml", "npm"},
		{"Cargo.lock", "Rust"},
		{"Gemfile.lock", "RubyGems"},
		{"requirements.txt", "PyPI"},
		{"poetry.lock", "PyPI"},
		{"composer.lock", "Packagist"},
	}

	var found []lockfileInfo
	for _, lf := range known {
		path := filepath.Join(dir, lf.filename)
		if _, err := os.Stat(path); err == nil {
			found = append(found, lockfileInfo{file: lf.filename, ecosystem: lf.ecosystem})
		}
	}
	return found
}

func detectCI(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
		return "GitHub Actions"
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitlab-ci.yml")); err == nil {
		return "GitLab CI"
	}
	if _, err := os.Stat(filepath.Join(dir, "Jenkinsfile")); err == nil {
		return "Jenkins"
	}
	if _, err := os.Stat(filepath.Join(dir, ".circleci")); err == nil {
		return "CircleCI"
	}
	return ""
}

func printCISnippet(ci string) {
	switch ci {
	case "GitHub Actions":
		fmt.Fprintf(os.Stderr, "\nSuggested workflow step:\n")
		fmt.Fprintf(os.Stderr, "  - name: Vulnerability scan\n")
		fmt.Fprintf(os.Stderr, "    run: vulnex scan go.sum --enrich --policy .vulnex-policy.yaml\n")
	case "GitLab CI":
		fmt.Fprintf(os.Stderr, "\nSuggested job:\n")
		fmt.Fprintf(os.Stderr, "  vulnex-scan:\n")
		fmt.Fprintf(os.Stderr, "    script:\n")
		fmt.Fprintf(os.Stderr, "      - vulnex scan go.sum --enrich --policy .vulnex-policy.yaml\n")
	}
}

const defaultPolicy = `version: 1
rules:
  - name: block-kev
    match:
      kev: true
    action: fail

  - name: block-critical-epss
    match:
      severity:
        - CRITICAL
      epss_gte: 0.7
    action: fail

  - name: warn-high-severity
    match:
      severity:
        - HIGH
    action: warn
`

const defaultIgnore = `# Suppression file for vulnex
# See: https://github.com/AnasSahel/vulnex#vulnexignore
suppressions: []
`

func init() {
	rootCmd.AddCommand(initCmd)
}
