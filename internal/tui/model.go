package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type TickMsg time.Time

func Tick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

type RootModel struct {
	statusText string
}

func NewRootModel() RootModel {
	return RootModel{
		statusText: "Initializing subsystems...",
	}
}

func (m RootModel) Init() tea.Cmd {
	return Tick()
}

func (m RootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
	case TickMsg:
		m.statusText = "Loading panels... Active Tick: " + time.Time(msg).Format("15:04:05.000")
		return m, Tick()
	}
	return m, nil
}

func (m RootModel) View() string {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#5F5FDF")).
		Padding(0, 1)

	statusStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A0A0A0")).
		Italic(true)

	doc := lipgloss.JoinVertical(
		lipgloss.Left,
		headerStyle.Render("hyperview — Real-Time Monitor"),
		"",
		statusStyle.Render(m.statusText),
		"",
		"Press 'q' or 'Esc' to exit application cleanly.",
	)
	return doc
}
