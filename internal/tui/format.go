package tui

import (
	"fmt"
	"image/color"
	"math"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// fmtBytes formats a byte count with binary units.
func fmtBytes(b float64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%.0fB", b)
	}
	exp := 0
	for v := b / unit; v >= unit && exp < 5; v /= unit {
		exp++
	}
	v := b / math.Pow(unit, float64(exp+1))
	suffix := "KMGTPE"[exp : exp+1]
	if v >= 100 {
		return fmt.Sprintf("%.0f%s", v, suffix)
	}
	return fmt.Sprintf("%.1f%s", v, suffix)
}

func fmtKiB(k uint64) string { return fmtBytes(float64(k) * 1024) }

// fmtRate formats a bytes/s rate.
func fmtRate(b float64) string { return fmtBytes(b) + "/s" }

// fmtNum formats a count with k/M suffixes.
func fmtNum(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.0fk", v/1e3)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	case v >= 10 || v == 0:
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

func fmtUs(us float64) string {
	switch {
	case us <= 0:
		return "–"
	case us >= 1e6:
		return fmt.Sprintf("%.2fs", us/1e6)
	case us >= 1e3:
		return fmt.Sprintf("%.1fms", us/1e3)
	}
	return fmt.Sprintf("%.0fµs", us)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// sparkline renders the last width values scaled to ceil (or the series
// maximum when ceil is 0), colored with c.
func sparkline(vals []float64, width int, ceil float64, c color.Color) string {
	if width <= 0 {
		return ""
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	top := ceil
	if top <= 0 {
		for _, v := range vals {
			top = max(top, v)
		}
		top *= 1.15
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", width-len(vals)))
	for _, v := range vals {
		if top <= 0 || v <= 0 {
			b.WriteRune(' ')
			continue
		}
		i := int(math.Round(v / top * float64(len(sparkRunes)-1)))
		b.WriteRune(sparkRunes[min(max(i, 0), len(sparkRunes)-1)])
	}
	return fg(c).Render(b.String())
}

// areaChart renders vals as a filled chart rows lines tall.
func areaChart(vals []float64, width, rows int, ceil float64, c color.Color) string {
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	top := ceil
	if top <= 0 {
		for _, v := range vals {
			top = max(top, v)
		}
		top *= 1.15 // headroom so a flat series does not fill the chart
	}
	pad := width - len(vals)
	levels := make([]int, len(vals))
	for i, v := range vals {
		if top > 0 && v > 0 {
			levels[i] = max(int(math.Round(v/top*float64(rows*8))), 1)
		}
	}
	lines := make([]string, rows)
	for r := range rows {
		base := (rows - 1 - r) * 8 // eighths below this row
		var b strings.Builder
		b.WriteString(strings.Repeat(" ", pad))
		for _, l := range levels {
			switch n := l - base; {
			case n >= 8:
				b.WriteRune('█')
			case n <= 0:
				b.WriteRune(' ')
			default:
				b.WriteRune(sparkRunes[n-1])
			}
		}
		lines[r] = fg(c).Render(b.String())
	}
	return strings.Join(lines, "\n")
}

// bar renders a horizontal gauge of width cells filled to frac.
func bar(frac float64, width int, c color.Color) string {
	if width <= 0 {
		return ""
	}
	frac = min(max(frac, 0), 1)
	cells := frac * float64(width)
	full := int(cells)
	var b strings.Builder
	b.WriteString(strings.Repeat("█", full))
	parts := []rune(" ▏▎▍▌▋▊▉")
	if full < width {
		b.WriteRune(parts[int((cells-float64(full))*8)])
		full++
	}
	filled := fg(c).Render(b.String())
	return filled + stDim.Render(strings.Repeat("·", width-full))
}

// fit truncates or pads s to exactly w cells.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "…")
	if pad := w - lipgloss.Width(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return s
}

// fitRight right-aligns s in w cells.
func fitRight(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "…")
	if pad := w - lipgloss.Width(s); pad > 0 {
		s = strings.Repeat(" ", pad) + s
	}
	return s
}

// spread places left and right on one line of width w.
func spread(left, right string, w int) string {
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return fit(left, w-lipgloss.Width(right)-1) + " " + right
	}
	return left + strings.Repeat(" ", gap) + right
}

// column is a table column. Fixed columns have a width; flexible ones
// (flex > 0) share the remaining space, between min and max cells. When
// the table does not fit, columns with the lowest prio are hidden first;
// prio 0 columns are never hidden.
type column struct {
	title string
	width int
	right bool
	prio  int
	flex  int
	min   int
	max   int
}

// layout computes column widths for a table w cells wide. Hidden columns
// get width 0 and are skipped by renderRow.
func layout(cols []column, w int) []column {
	cols = append([]column(nil), cols...)
	need := func() int {
		n := 0
		for _, c := range cols {
			switch {
			case c.flex > 0 && c.min >= 0:
				n += c.min + 1
			case c.width > 0:
				n += c.width + 1
			}
		}
		return n
	}
	for need() > w {
		drop := -1
		for i, c := range cols {
			visible := c.width > 0 || (c.flex > 0 && c.min >= 0)
			if visible && c.prio > 0 && (drop < 0 || c.prio < cols[drop].prio) {
				drop = i
			}
		}
		if drop < 0 {
			break
		}
		cols[drop].width, cols[drop].min = 0, -1
		if cols[drop].flex > 0 {
			cols[drop].flex = 0
		}
	}
	spare := w - need()
	weights := 0
	for _, c := range cols {
		weights += c.flex
	}
	// Hand out spare cells by weight, capping at max; leftovers from capped
	// columns go to the uncapped ones.
	for i := range cols {
		if cols[i].flex > 0 {
			cols[i].width = cols[i].min
		}
	}
	for pass := 0; pass < 3 && spare > 0 && weights > 0; pass++ {
		given, nextWeights := 0, 0
		for i := range cols {
			c := &cols[i]
			if c.flex == 0 || (c.max > 0 && c.width >= c.max) {
				continue
			}
			add := spare * c.flex / weights
			if c.max > 0 {
				add = min(add, c.max-c.width)
			}
			c.width += add
			given += add
			if c.max == 0 || c.width < c.max {
				nextWeights += c.flex
			}
		}
		spare -= given
		weights = nextWeights
		if given == 0 {
			break
		}
	}
	return cols
}

func titles(cols []column) []string {
	t := make([]string, len(cols))
	for i, c := range cols {
		t[i] = c.title
	}
	return t
}
