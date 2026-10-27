// Package tui is hyperview's terminal interface.
package tui

import (
	"cmp"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"hyperview/internal/alert"
	"hyperview/internal/config"
	"hyperview/internal/probe"
	"hyperview/internal/store"
)

// Sources is everything the UI reads. Functions may be nil.
type Sources struct {
	Store   *store.DomainStore
	Alerts  *alert.Engine
	Config  config.Config
	Probes  func() []probe.Status
	EBPF    func() (ok bool, reason string)
	Kmsg    func() string // empty while following, otherwise why not
	Libvirt func() string // connected socket, empty when not connected
}

type screen int

const (
	scrDashboard screen = iota
	scrDetail
	scrAlerts
	scrStatus
	scrLog
)

type sortKey int

const (
	sortName sortKey = iota
	sortCPU
	sortMem
	sortNet
	sortDisk
	sortAlerts
)

var sortNames = []string{"name", "cpu", "mem", "net", "disk", "alerts"}

type tickMsg time.Time

type Model struct {
	src Sources

	width, height int
	screen        screen
	help          bool

	// Data refreshed every tick.
	now     time.Time
	host    store.HostStat
	hostH   store.HostHistory
	doms    []store.DomainSnapshot
	visible []store.DomainSnapshot
	counts  map[string]alert.DomainCount
	alerts  []alert.Alert

	// Dashboard.
	cursor    int
	selID     string
	sort      sortKey
	reverse   bool
	filter    string
	filtering bool

	// Detail.
	tab int

	// Alerts and log views.
	alertCursor int
	alertMin    alert.Severity
	scroll      int
}

func New(src Sources, filter string) *Model {
	m := &Model{src: src, filter: filter, width: 120, height: 40}
	m.refresh()
	return m
}

func (m *Model) Init() tea.Cmd { return m.tick() }

func (m *Model) tick() tea.Cmd {
	return tea.Tick(m.src.Config.Interval.Duration, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) refresh() {
	m.now = time.Now()
	m.host = m.src.Store.Host()
	m.hostH = m.src.Store.HostHistory()
	m.doms = m.src.Store.Snapshot()
	m.counts = m.src.Alerts.DomainCounts()
	m.alerts = m.src.Alerts.Recent(0)
	m.applyView()
}

// applyView filters and sorts domains and keeps the selection on the same
// VM when rows move.
func (m *Model) applyView() {
	f := strings.ToLower(m.filter)
	m.visible = m.visible[:0]
	for _, d := range m.doms {
		if f == "" || strings.Contains(strings.ToLower(d.Name), f) || strings.Contains(strings.ToLower(d.Source), f) {
			m.visible = append(m.visible, d)
		}
	}
	key := func(d *store.DomainSnapshot) float64 {
		switch m.sort {
		case sortCPU:
			return d.CPUPercent()
		case sortMem:
			return float64(max(d.Mem.RssKiB, d.Mem.BalloonKiB))
		case sortNet:
			rx, tx := d.NetRates()
			return rx + tx
		case sortDisk:
			rd, wr := d.DiskRates()
			return rd + wr
		case sortAlerts:
			c := m.counts[d.ID]
			return float64(c.Worst)*1e6 + float64(c.N)
		}
		return 0
	}
	slices.SortStableFunc(m.visible, func(a, b store.DomainSnapshot) int {
		var c int
		if m.sort == sortName {
			c = cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		} else {
			c = cmp.Compare(key(&b), key(&a)) // numeric keys: biggest first
		}
		if m.reverse {
			c = -c
		}
		return c
	})
	m.cursor = 0
	for i, d := range m.visible {
		if d.ID == m.selID {
			m.cursor = i
		}
	}
	m.syncSel()
}

func (m *Model) syncSel() {
	if len(m.visible) == 0 {
		m.cursor, m.selID = 0, ""
		return
	}
	m.cursor = min(max(m.cursor, 0), len(m.visible)-1)
	m.selID = m.visible[m.cursor].ID
}

func (m *Model) selected() (store.DomainSnapshot, bool) {
	for _, d := range m.doms {
		if d.ID == m.selID {
			return d, true
		}
	}
	return store.DomainSnapshot{}, false
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		m.refresh()
		return m, m.tick()
	case tea.KeyPressMsg:
		return m, m.key(msg.String())
	case tea.MouseWheelMsg:
		switch msg.Mouse().Button {
		case tea.MouseWheelUp:
			m.move(-1)
		case tea.MouseWheelDown:
			m.move(1)
		}
	}
	return m, nil
}

func (m *Model) key(k string) tea.Cmd {
	if k == "ctrl+c" {
		return tea.Quit
	}
	if m.filtering {
		m.filterKey(k)
		return nil
	}
	if m.help {
		m.help = false
		return nil
	}
	switch k {
	case "q":
		if m.screen == scrDashboard {
			return tea.Quit
		}
		m.back()
	case "esc", "backspace":
		if m.screen == scrDashboard && m.filter != "" {
			m.filter = ""
			m.applyView()
		}
		m.back()
	case "?":
		m.help = true
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup", "ctrl+u":
		m.move(-m.pageSize())
	case "pgdown", "ctrl+d":
		m.move(m.pageSize())
	case "home", "g":
		m.move(-1 << 30)
	case "end", "G":
		m.move(1 << 30)
	case "a":
		m.open(scrAlerts)
	case "p":
		m.open(scrStatus)
	case "L":
		m.open(scrLog)
	}

	switch m.screen {
	case scrDashboard:
		switch k {
		case "enter", "right", "l":
			if m.selID != "" {
				m.screen, m.tab = scrDetail, 0
			}
		case "/":
			m.filtering = true
		case "s":
			m.sort = (m.sort + 1) % sortKey(len(sortNames))
			m.applyView()
		case "r":
			m.reverse = !m.reverse
			m.applyView()
		}
	case scrDetail:
		tabs := m.detailTabs()
		switch k {
		case "right", "l", "tab":
			m.tab = (m.tab + 1) % len(tabs)
		case "left", "h", "shift+tab":
			m.tab = (m.tab + len(tabs) - 1) % len(tabs)
		default:
			if len(k) == 1 && k[0] >= '1' && k[0] <= '9' {
				if i := int(k[0] - '1'); i < len(tabs) {
					m.tab = i
				}
			}
		}
	case scrAlerts:
		if k == "f" {
			m.alertMin = (m.alertMin + 1) % 3
			m.alertCursor = 0
		}
	}
	return nil
}

func (m *Model) filterKey(k string) {
	switch k {
	case "enter":
		m.filtering = false
	case "esc":
		m.filtering, m.filter = false, ""
	case "backspace":
		if r := []rune(m.filter); len(r) > 0 {
			m.filter = string(r[:len(r)-1])
		}
	case "space":
		m.filter += " "
	default:
		if r := []rune(k); len(r) == 1 {
			m.filter += k
		}
	}
	m.applyView()
}

func (m *Model) open(s screen) {
	if m.screen == s {
		m.back()
		return
	}
	m.screen, m.scroll, m.alertCursor = s, 0, 0
}

func (m *Model) back() {
	m.screen, m.scroll = scrDashboard, 0
}

func (m *Model) pageSize() int { return max(m.height/2, 1) }

func (m *Model) move(n int) {
	switch m.screen {
	case scrDashboard:
		m.cursor += n
		m.syncSel()
	case scrAlerts:
		m.alertCursor = min(max(m.alertCursor+n, 0), max(len(m.filteredAlerts())-1, 0))
	default:
		m.scroll = max(m.scroll+n, 0)
	}
}

func (m *Model) View() tea.View {
	var body string
	switch m.screen {
	case scrDetail:
		if d, ok := m.selected(); ok {
			body = m.viewDetail(d)
		} else {
			m.screen = scrDashboard
			body = m.viewDashboard()
		}
	case scrAlerts:
		body = m.viewAlerts()
	case scrStatus:
		body = m.viewStatus()
	case scrLog:
		body = m.viewLog()
	default:
		body = m.viewDashboard()
	}
	if m.help {
		body = m.overlay(body, m.viewHelp())
	}
	v := tea.NewView(m.canvas(body))
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.BackgroundColor = colBg
	v.WindowTitle = "hyperview — " + m.host.Hostname
	return v
}

// canvas clips body to the window and paints the background.
func (m *Model) canvas(body string) string {
	lines := strings.Split(body, "\n")
	if len(lines) > m.height {
		lines = lines[:m.height]
	}
	for i, l := range lines {
		lines[i] = fit(l, m.width)
	}
	return lipgloss.NewStyle().Background(colBg).Foreground(colFg).
		Width(m.width).Height(m.height).Render(strings.Join(lines, "\n"))
}

// overlay centers box over body.
func (m *Model) overlay(body, box string) string {
	lines := strings.Split(body, "\n")
	for len(lines) < m.height {
		lines = append(lines, "")
	}
	boxLines := strings.Split(box, "\n")
	bw := lipgloss.Width(box)
	x := max((m.width-bw)/2, 0)
	y := max((m.height-len(boxLines))/2, 0)
	for i, bl := range boxLines {
		if y+i >= len(lines) {
			break
		}
		l := fit(lines[y+i], m.width)
		lines[y+i] = ansi.Truncate(l, x, "") + bl + ansi.TruncateLeft(l, x+bw, "")
	}
	return strings.Join(lines, "\n")
}
