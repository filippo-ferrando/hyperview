package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"

	"hyperview/internal/alert"
)

// Fixed dark palette. The view also sets the terminal background, so the
// palette looks the same on light terminals.
var (
	colBg       = lipgloss.Color("#0f1218")
	colPanel    = lipgloss.Color("#151a22")
	colSel      = lipgloss.Color("#232b3a")
	colBorder   = lipgloss.Color("#2b3341")
	colFg       = lipgloss.Color("#c8d0dc")
	colMuted    = lipgloss.Color("#6b7686")
	colDim      = lipgloss.Color("#465061")
	colAccent   = lipgloss.Color("#7aa2f7")
	colCyan     = lipgloss.Color("#7dcfff")
	colGreen    = lipgloss.Color("#9ece6a")
	colAmber    = lipgloss.Color("#e0af68")
	colRed      = lipgloss.Color("#f7768e")
	colPurple   = lipgloss.Color("#bb9af7")
	colRx       = lipgloss.Color("#73daca")
	colTx       = lipgloss.Color("#bb9af7")
	colTitleBar = lipgloss.Color("#1b2130")
)

var (
	stBase    = lipgloss.NewStyle().Foreground(colFg)
	stMuted   = lipgloss.NewStyle().Foreground(colMuted)
	stDim     = lipgloss.NewStyle().Foreground(colDim)
	stBold    = lipgloss.NewStyle().Foreground(colFg).Bold(true)
	stAccent  = lipgloss.NewStyle().Foreground(colAccent)
	stLabel   = lipgloss.NewStyle().Foreground(colMuted)
	stTitle   = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	stHeadRow = lipgloss.NewStyle().Foreground(colMuted).Bold(true)
	stKey     = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	stTabOn   = lipgloss.NewStyle().Foreground(colBg).Background(colAccent).Bold(true).Padding(0, 1)
	stTabOff  = lipgloss.NewStyle().Foreground(colMuted).Padding(0, 1)
	stBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).Padding(0, 1)
	stBoxHot  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colAccent).Padding(0, 1)
)

func fg(c color.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

func severityColor(s alert.Severity) color.Color {
	switch s {
	case alert.Critical:
		return colRed
	case alert.Warning:
		return colAmber
	}
	return colAccent
}

func severityIcon(s alert.Severity) string {
	switch s {
	case alert.Critical:
		return "✖"
	case alert.Warning:
		return "▲"
	}
	return "●"
}

// stateStyle colors a VM run state.
func stateColor(state, reason string) color.Color {
	switch state {
	case "running":
		return colGreen
	case "paused", "pmsuspended", "blocked":
		switch reason {
		case "ioerror", "io-error", "watchdog", "crashed", "internal-error", "postcopy failed":
			return colRed
		}
		return colAmber
	case "crashed":
		return colRed
	}
	return colDim
}

// levelColor grades v against warn/crit levels.
func levelColor(v, warn, crit float64) color.Color {
	switch {
	case crit > 0 && v >= crit:
		return colRed
	case warn > 0 && v >= warn:
		return colAmber
	}
	return colGreen
}
