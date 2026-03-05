package cmd

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// cmdStyles holds lipgloss styles for command output that bypasses the formatter.
type cmdStyles struct {
	header   lipgloss.Style // bold blue section headers
	label    lipgloss.Style // bold left-aligned labels
	value    lipgloss.Style // normal text
	success  lipgloss.Style // green confirmations
	cveID    lipgloss.Style // blue CVE identifiers
	critical lipgloss.Style
	high     lipgloss.Style
	medium   lipgloss.Style
	low      lipgloss.Style
	muted    lipgloss.Style
}

func newCmdStyles(noColor bool) cmdStyles {
	if noColor {
		return cmdStyles{
			header:   lipgloss.NewStyle().Bold(true),
			label:    lipgloss.NewStyle().Bold(true).Width(20),
			value:    lipgloss.NewStyle(),
			success:  lipgloss.NewStyle(),
			cveID:    lipgloss.NewStyle(),
			critical: lipgloss.NewStyle(),
			high:     lipgloss.NewStyle(),
			medium:   lipgloss.NewStyle(),
			low:      lipgloss.NewStyle(),
			muted:    lipgloss.NewStyle(),
		}
	}
	return cmdStyles{
		header:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")),
		label:    lipgloss.NewStyle().Bold(true).Width(20),
		value:    lipgloss.NewStyle(),
		success:  lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		cveID:    lipgloss.NewStyle().Foreground(lipgloss.Color("12")),
		critical: lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true),
		high:     lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		medium:   lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		low:      lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		muted:    lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

func (s cmdStyles) severity(sev string) lipgloss.Style {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return s.critical
	case "HIGH":
		return s.high
	case "MEDIUM":
		return s.medium
	case "LOW":
		return s.low
	default:
		return s.muted
	}
}

// priorityStyle returns a style for P0-P4 priority labels.
func (s cmdStyles) priority(p string) lipgloss.Style {
	switch {
	case strings.HasPrefix(p, "P0"):
		return s.critical
	case strings.HasPrefix(p, "P1"):
		return s.high
	case strings.HasPrefix(p, "P2"):
		return s.medium
	case strings.HasPrefix(p, "P3"):
		return s.low
	default:
		return s.muted
	}
}
