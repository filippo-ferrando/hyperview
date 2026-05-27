package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"hyperview/internal/store"
	"hyperview/internal/tui/panels"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type TickMsg time.Time

type RootModel struct {
	store        *store.DomainStore
	table        table.Model
	selectedID   string
	isDetailView bool
	activeTab    int
	sortColumn   int
	sortReverse  bool
	isPaused     bool
	showHelp     bool // NEW (Phase 6 Overlay Switch)
	showLogs     bool // NEW (Phase 6 Overlay Switch)
	domainFilter string
	tickDuration time.Duration
	width        int
	height       int
}

func NewRootModel(s *store.DomainStore) RootModel {
	columns := []table.Column{
		{Title: "Name", Width: 16},
		{Title: "State", Width: 12},
		{Title: "vCPUs", Width: 6},
		{Title: "CPU%", Width: 8},
		{Title: "Mem", Width: 10},
		{Title: "Net↓", Width: 10},
		{Title: "Net↑", Width: 10},
		{Title: "Disk I/O", Width: 12},
	}
	t := table.New(table.WithColumns(columns), table.WithFocused(true), table.WithHeight(10))
	sStyle := table.DefaultStyles()
	sStyle.Header = sStyle.Header.Background(lipgloss.Color("#5F5FDF")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	sStyle.Selected = sStyle.Selected.Background(lipgloss.Color("#5F5F5F")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	t.SetStyles(sStyle)
	return RootModel{store: s, table: t, tickDuration: 250 * time.Millisecond}
}

func (m *RootModel) SetTickInterval(d time.Duration) { m.tickDuration = d }
func (m *RootModel) SetDomainFilter(f string)        { m.domainFilter = f }

func (m RootModel) Init() tea.Cmd {
	return tea.Tick(m.tickDuration, func(t time.Time) tea.Msg { return TickMsg(t) })
}

func (m RootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		// Modal checks to intercept standard input routing mechanisms
		if m.showHelp || m.showLogs {
			switch msg.String() {
			case "q", "esc", "?", "l":
				m.showHelp = false
				m.showLogs = false
				return m, nil
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = true
			return m, nil
		case "l":
			m.showLogs = true
			return m, nil
		case "esc":
			if m.isDetailView {
				m.isDetailView = false
				return m, nil
			}
			return m, tea.Quit
		case "enter":
			if !m.isDetailView && len(m.table.Rows()) > 0 {
				m.isDetailView = true
				m.selectedID = m.table.SelectedRow()[0]
			}
		case "tab":
			if m.isDetailView {
				m.activeTab = (m.activeTab + 1) % 6
			}
		case "s":
			if !m.isDetailView {
				m.sortColumn = (m.sortColumn + 1) % 8
				m.refreshTableData()
			}
		case "r":
			if !m.isDetailView {
				m.sortReverse = !m.sortReverse
				m.refreshTableData()
			}
		case "p":
			m.isPaused = !m.isPaused
		}
	case TickMsg:
		if !m.isPaused {
			m.refreshTableData()
		}
		return m, tea.Tick(m.tickDuration, func(t time.Time) tea.Msg { return TickMsg(t) })
	}
	if !m.isDetailView && !m.showHelp && !m.showLogs {
		m.table, cmd = m.table.Update(msg)
	}
	return m, cmd
}

func (m *RootModel) refreshTableData() {
	snaps := m.store.Snapshot()

	// Apply start domain filter query strings if actively initialized
	if m.domainFilter != "" {
		var filtered []store.DomainSnapshot
		for _, s := range snaps {
			if strings.Contains(strings.ToLower(s.Name), strings.ToLower(m.domainFilter)) {
				filtered = append(filtered, s)
			}
		}
		snaps = filtered
	}

	sort.Slice(snaps, func(i, j int) bool {
		var less bool
		switch m.sortColumn {
		case 0:
			less = snaps[i].Name < snaps[j].Name
		case 1:
			less = snaps[i].State < snaps[j].State
		case 2:
			less = len(snaps[i].VCPUs) < len(snaps[j].VCPUs)
		case 3:
			var cI, cJ float64
			for _, v := range snaps[i].VCPUs {
				cI += v.CPUPercent
			}
			for _, v := range snaps[j].VCPUs {
				cJ += v.CPUPercent
			}
			less = cI < cJ
		case 4:
			less = snaps[i].Mem.RssKiB < snaps[j].Mem.RssKiB
		case 5:
			var rxI, rxJ uint64
			for _, f := range snaps[i].Ifaces {
				rxI += f.RxBytes
			}
			for _, f := range snaps[j].Ifaces {
				rxJ += f.RxBytes
			}
			less = rxI < rxJ
		case 6:
			var txI, txJ uint64
			for _, f := range snaps[i].Ifaces {
				txI += f.TxBytes
			}
			for _, f := range snaps[j].Ifaces {
				txJ += f.TxBytes
			}
			less = txI < txJ
		case 7:
			var ioI, ioJ uint64
			for _, d := range snaps[i].Disks {
				ioI += d.RdBytes + d.WrBytes
			}
			for _, d := range snaps[j].Disks {
				ioJ += d.RdBytes + d.WrBytes
			}
			less = ioI < ioJ
		default:
			less = snaps[i].Name < snaps[j].Name
		}
		if m.sortReverse {
			return !less
		}
		return less
	})

	var rows []table.Row
	for _, snap := range snaps {
		var totalCPU float64
		for _, vcpu := range snap.VCPUs {
			totalCPU += vcpu.CPUPercent
		}
		var totalRx, totalTx, totalIO uint64
		for _, f := range snap.Ifaces {
			totalRx += f.RxBytes
			totalTx += f.TxBytes
		}
		for _, d := range snap.Disks {
			totalIO += d.RdBytes + d.WrBytes
		}

		stateLabel := snap.State
		if snap.Migration != nil && snap.Migration.Status == "active" {
			stateLabel = fmt.Sprintf("%s ⇄", snap.State)
		}

		rows = append(rows, table.Row{
			snap.Name, stateLabel, fmt.Sprintf("%d", len(snap.VCPUs)), fmt.Sprintf("%5.1f%%", totalCPU),
			fmt.Sprintf("%d MiB", snap.Mem.RssKiB/1024), panels.FormatBytes(totalRx), panels.FormatBytes(totalTx), panels.FormatBytes(totalIO),
		})
	}
	m.table.SetRows(rows)
}

func (m RootModel) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#5F5FDF")).Padding(0, 1)
	footerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#707070")).Italic(true)
	modalStyle := lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(lipgloss.Color("#FFAF00")).Padding(1, 3).Background(lipgloss.Color("#1C1C1C")).Width(70)

	// 1. Render Help Overlay Modal
	if m.showHelp {
		helpContent := lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFAF00")).Render("HYPERVIEW INTERACTIVE KEYBOARD COMMANDS REFERENCE"),
			"",
			"  ↑ / ↓   ➔ Navigate and select virtualization targets inside index list",
			"  Enter   ➔ Drill down into comprehensive metrics of selected node",
			"  Tab     ➔ Cycle cross-sectional views inside selected cluster sub-panels",
			"  s       ➔ Rotate table data matching next statistics field index",
			"  r       ➔ Toggle inverse collection list sorting logic",
			"  p       ➔ Pause/Resume active monitor background evaluation frames",
			"  l       ➔ Toggle application runtime logs capture modal",
			"  ?       ➔ Show this reference manual information summary overlay box",
			"  Esc     ➔ Collapse detail sub-panes or quit core console binary",
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("#707070")).Render("Press any modal control switch (?|l|Esc) to clear view context."),
		)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modalStyle.Render(helpContent))
	}

	// 2. Render Log Overlay Modal
	if m.showLogs {
		logLines := GlobalLogRing.GetTail(15)
		logBoxContent := lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFAF00")).Render("REAL-TIME STRUCTURED RUNTIME TRANSACTION LOGS"),
			"",
			strings.Join(logLines, ""),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("#707070")).Render("Press any modal control switch (?|l|Esc) to clear view context."),
		)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modalStyle.Width(m.width-10).Render(logBoxContent))
	}

	pauseText := ""
	if m.isPaused {
		pauseText = " [PAUSED]"
	}

	ebpfIndicator := " [eBPF ✗ (fallback)]"
	for _, snap := range m.store.Snapshot() {
		if snap.KVMEvents.Available {
			ebpfIndicator = " [eBPF ✓]"
			break
		}
	}

	if m.isDetailView {
		var snap store.DomainSnapshot
		var exists bool
		for _, s := range m.store.Snapshot() {
			if s.Name == m.selectedID {
				snap = s
				exists = true
				break
			}
		}
		if !exists {
			return "Selected domain snapshot missing. Press Esc to go back."
		}

		history := m.store.History(snap.ID)
		tabStyle := lipgloss.NewStyle().Padding(0, 1).Background(lipgloss.Color("#303030"))
		activeTabStyle := tabStyle.Copy().Background(lipgloss.Color("#5F5FDF")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true)

		tabRow := lipgloss.JoinHorizontal(
			lipgloss.Top,
			func() string {
				if m.activeTab == 0 {
					return activeTabStyle.Render("1. vCPU")
				}
				return tabStyle.Render("1. vCPU")
			}(),
			func() string {
				if m.activeTab == 1 {
					return activeTabStyle.Render("2. Memory")
				}
				return tabStyle.Render("2. Memory")
			}(),
			func() string {
				if m.activeTab == 2 {
					return activeTabStyle.Render("3. Network")
				}
				return tabStyle.Render("3. Network")
			}(),
			func() string {
				if m.activeTab == 3 {
					return activeTabStyle.Render("4. Storage I/O")
				}
				return tabStyle.Render("4. Storage I/O")
			}(),
			func() string {
				if m.activeTab == 4 {
					return activeTabStyle.Render("5. KVM Exits")
				}
				return tabStyle.Render("5. KVM Exits")
			}(),
			func() string {
				if m.activeTab == 5 {
					return activeTabStyle.Render("6. Migration")
				}
				return tabStyle.Render("6. Migration")
			}(),
		)

		var currentPanel string
		switch m.activeTab {
		case 0:
			currentPanel = panels.RenderCPUPanel(snap, m.width)
		case 1:
			currentPanel = panels.RenderMemPanel(snap)
		case 2:
			currentPanel = panels.RenderNetPanel(snap, history)
		case 3:
			currentPanel = panels.RenderIOPanel(snap)
		case 4:
			currentPanel = panels.RenderKVMPanel(snap, m.width)
		case 5:
			currentPanel = panels.RenderMigrationPanel(snap, m.width)
		}

		contentBox := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#5F5FDF")).Padding(1, 2).Width(m.width - 4).Render(currentPanel)
		return lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render(fmt.Sprintf("hyperview Dashboard > Node: %s%s%s", snap.Name, ebpfIndicator, pauseText)), "", tabRow, contentBox, "", footerStyle.Render("➔ Tab: Cycle Detail Panels · P: Toggle Pause · L: Show Logs · ?: Key Bindings · Esc: Return"))
	}

	sortText := fmt.Sprintf(" [Sorted by: %s]", m.table.Columns()[m.sortColumn].Title)
	if m.sortReverse {
		sortText += " (Reverse)"
	}
	return lipgloss.JoinVertical(lipgloss.Left, headerStyle.Render(fmt.Sprintf("hyperview — Active Hypervisor Monitor%s%s%s", sortText, ebpfIndicator, pauseText)), "", m.table.View(), "", footerStyle.Render("➔ Navigation: ↑/↓ Browse · Enter Inspect · S Sort · R Reverse · P Pause · L Logs · ?: Help · Q Quit"))
}
