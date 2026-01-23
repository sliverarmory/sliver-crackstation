package tui

import (
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
)

type viewMode uint

const (
	viewSummary viewMode = iota
	viewDetail
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	stateStyleWaiting = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Padding(0, 1)
	stateStyleActive  = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true).Padding(0, 1)
	stateStyleIdle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Bold(true).Padding(0, 1)

	boxStyle = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).Padding(0, 1)
)

type statusMsg *clientpb.CrackstationStatus

type crackstationModel struct {
	crack      *crackstation.Crackstation
	status     *clientpb.CrackstationStatus
	statusSub  chan *clientpb.CrackstationStatus
	lastUpdate time.Time
	spinner    spinner.Model
	view       viewMode
	width      int
	height     int
}

func StartTUI(crack *crackstation.Crackstation) {
	go crack.Start()
	defer crack.Stop()

	statusSub := crack.StatusBroker.Subscribe()
	defer crack.StatusBroker.Unsubscribe(statusSub)

	p := tea.NewProgram(newModel(crack, statusSub), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func StartLogOnly(crack *crackstation.Crackstation, out io.Writer) {
	go crack.Start()
	defer crack.Stop()

	statusSub := crack.StatusBroker.Subscribe()
	defer crack.StatusBroker.Unsubscribe(statusSub)

	for status := range statusSub {
		fmt.Fprintln(out, formatStatusLine(status, time.Now()))
	}
}

func newModel(crack *crackstation.Crackstation, statusSub chan *clientpb.CrackstationStatus) crackstationModel {
	spin := spinner.New()
	spin.Spinner = spinner.Line
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	return crackstationModel{
		crack:      crack,
		status:     crack.Status(),
		statusSub:  statusSub,
		lastUpdate: time.Now(),
		spinner:    spin,
		view:       viewSummary,
	}
}

func (m crackstationModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForStatus(m.statusSub))
}

func (m crackstationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			if m.view == viewSummary {
				m.view = viewDetail
			} else {
				m.view = viewSummary
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case statusMsg:
		m.status = (*clientpb.CrackstationStatus)(msg)
		m.lastUpdate = time.Now()
		return m, waitForStatus(m.statusSub)
	}
	return m, nil
}

func (m crackstationModel) View() string {
	header := m.renderHeader()
	body := m.renderBody()
	footer := helpStyle.Render("q: quit  tab: toggle view")
	return strings.Join([]string{header, body, footer}, "\n\n")
}

func (m crackstationModel) renderHeader() string {
	state := "UNKNOWN"
	if m.status != nil {
		state = m.status.GetState().String()
	}
	stateBadge := stateBadge(state)
	activity := ""
	if m.isActive() {
		activity = m.spinner.View()
	}

	title := titleStyle.Render("Sliver Crackstation Monitor")
	line := strings.TrimSpace(strings.Join([]string{title, activity, stateBadge}, " "))
	return line
}

func (m crackstationModel) renderBody() string {
	if m.status == nil {
		return boxStyle.Render("Waiting for status updates ...")
	}

	now := time.Now()
	lines := []string{
		formatLine("Name", m.status.GetName()),
		formatLine("Host UUID", m.status.GetHostUUID()),
		formatLine("State", m.status.GetState().String()),
		formatLine("Servers", fmt.Sprintf("%d", countServers(m.crack))),
		formatLine("Last Update", humanizeDuration(now.Sub(m.lastUpdate))+" ago"),
		formatLine("Cracking", crackSummary(m.status, now)),
		formatLine("Syncing", syncSummary(m.status)),
	}

	if m.view == viewDetail {
		detailLines := m.renderDetailLines()
		if len(detailLines) > 0 {
			lines = append(lines, "")
			lines = append(lines, detailLines...)
		}
	}

	return boxStyle.Width(m.contentWidth()).Render(strings.Join(lines, "\n"))
}

func (m crackstationModel) renderDetailLines() []string {
	if m.status == nil || !m.status.GetIsSyncing() || m.status.GetSyncing() == nil {
		return nil
	}

	progress := m.status.GetSyncing().GetProgress()
	if len(progress) == 0 {
		return []string{formatLine("Sync Progress", "No file progress reported")}
	}

	keys := make([]string, 0, len(progress))
	for key := range progress {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := []string{formatLine("Sync Progress", fmt.Sprintf("%d files", len(keys)))}
	maxLines := 6
	for i, key := range keys {
		if i >= maxLines {
			lines = append(lines, formatLine("...", fmt.Sprintf("%d more", len(keys)-maxLines)))
			break
		}
		lines = append(lines, formatLine(truncateString(key, 12), fmt.Sprintf("%.0f%%", progress[key]*100)))
	}
	return lines
}

func (m crackstationModel) contentWidth() int {
	if m.width <= 0 {
		return 80
	}
	return m.width - 4
}

func (m crackstationModel) isActive() bool {
	if m.status == nil {
		return false
	}
	return m.status.GetState() == clientpb.States_CRACKING || m.status.GetIsSyncing()
}

func countServers(crack *crackstation.Crackstation) int {
	if crack == nil || crack.Servers == nil {
		return 0
	}
	count := 0
	crack.Servers.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func waitForStatus(ch chan *clientpb.CrackstationStatus) tea.Cmd {
	return func() tea.Msg {
		status, ok := <-ch
		if !ok {
			return nil
		}
		return statusMsg(status)
	}
}

func formatStatusLine(status *clientpb.CrackstationStatus, now time.Time) string {
	if status == nil {
		return fmt.Sprintf("%s status unavailable", now.Format(time.RFC3339))
	}
	return fmt.Sprintf(
		"%s name=%s state=%s crack=%s sync=%s",
		now.Format(time.RFC3339),
		status.GetName(),
		status.GetState().String(),
		crackSummary(status, now),
		syncSummary(status),
	)
}

func crackSummary(status *clientpb.CrackstationStatus, now time.Time) string {
	if status == nil || status.GetState() != clientpb.States_CRACKING {
		return "idle"
	}
	if status.GetCurrentCrackJobID() == "" {
		return "active"
	}
	return status.GetCurrentCrackJobID()
}

func syncSummary(status *clientpb.CrackstationStatus) string {
	if status == nil || !status.GetIsSyncing() || status.GetSyncing() == nil {
		return "idle"
	}
	progress := status.GetSyncing().GetProgress()
	avg := averageProgress(progress)
	speed := humanizeRate(status.GetSyncing().GetSpeed())
	return fmt.Sprintf("%.0f%% across %d files @ %s", avg*100, len(progress), speed)
}

func averageProgress(progress map[string]float32) float32 {
	if len(progress) == 0 {
		return 0
	}
	var total float32
	for _, val := range progress {
		total += val
	}
	return total / float32(len(progress))
}

func formatLine(label, value string) string {
	return fmt.Sprintf("%s %s", labelStyle.Render(label+":"), valueStyle.Render(value))
}

func stateBadge(state string) string {
	switch state {
	case clientpb.States_INITIALIZING.String():
		return stateStyleWaiting.Render(state)
	case clientpb.States_CRACKING.String():
		return stateStyleActive.Render(state)
	default:
		return stateStyleIdle.Render(state)
	}
}

func humanizeRate(bytesPerSecond float32) string {
	return fmt.Sprintf("%s/s", humanizeBytes(bytesPerSecond))
}

func humanizeBytes(size float32) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%.0f B", size)
	}
	exp := 0
	for size >= unit && exp < 4 {
		size /= unit
		exp++
	}
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	return fmt.Sprintf("%.1f %s", size, suffixes[exp-1])
}

func humanizeDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours()/24), int(d.Hours())%24)
}

func truncateString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
