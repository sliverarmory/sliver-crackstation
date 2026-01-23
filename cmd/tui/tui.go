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
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
)

type viewMode uint

const (
	viewSummary viewMode = iota
	viewHost
	viewDevices
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	stateStyleWaiting = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Padding(0, 1)
	stateStyleActive  = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true).Padding(0, 1)
	stateStyleIdle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Bold(true).Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Padding(0, 1).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(false).
			BorderLeft(false).
			BorderRight(false).
			BorderTop(false)
	headerTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230"))
	headerMetaStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	tabActiveStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1).
			Bold(true)
	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("245")).
				Background(lipgloss.Color("236")).
				Padding(0, 1)
	tabBarStyle = lipgloss.NewStyle().Padding(0, 0, 0, 1)

	boxStyle = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).Padding(0, 1)
)

type statusMsg *clientpb.CrackstationStatus

type crackstationModel struct {
	crack       *crackstation.Crackstation
	status      *clientpb.CrackstationStatus
	statusSub   chan *clientpb.CrackstationStatus
	lastUpdate  time.Time
	spinner     spinner.Model
	view        viewMode
	confirming  bool
	confirmForm *huh.Form
	confirmQuit *bool
	width       int
	height      int
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
	confirmQuit := false
	return crackstationModel{
		crack:       crack,
		status:      crack.Status(),
		statusSub:   statusSub,
		lastUpdate:  time.Now(),
		spinner:     spin,
		view:        viewSummary,
		confirmQuit: &confirmQuit,
	}
}

func (m crackstationModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForStatus(m.statusSub))
}

func (m crackstationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.confirming && m.confirmForm != nil {
		var cmd tea.Cmd
		model, cmd := m.confirmForm.Update(msg)
		if updated, ok := model.(*huh.Form); ok {
			m.confirmForm = updated
		}
		switch m.confirmForm.State {
		case huh.StateCompleted:
			if m.confirmQuit != nil && *m.confirmQuit {
				return m, tea.Quit
			}
			m.confirming = false
			m.confirmForm = nil
			if m.confirmQuit != nil {
				*m.confirmQuit = false
			}
		case huh.StateAborted:
			m.confirming = false
			m.confirmForm = nil
			if m.confirmQuit != nil {
				*m.confirmQuit = false
			}
		}
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.confirming = true
			m.confirmForm = newQuitConfirmForm(m.confirmQuit)
			return m, m.confirmForm.Init()
		case "tab":
			m.view = (m.view + 1) % 3
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
	if m.confirming && m.confirmForm != nil {
		header := m.renderHeader()
		body := m.confirmForm.View()
		footer := helpStyle.Render("enter: submit  esc: cancel")
		return strings.Join([]string{header, body, footer}, "\n\n")
	}

	header := m.renderHeader()
	body := m.renderBody()
	footer := helpStyle.Render(fmt.Sprintf("q: quit  tab: next view  view: %s", m.viewName()))
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

	title := headerTitleStyle.Render("Sliver Crackstation Monitor")
	meta := headerMetaStyle.Render(m.viewName())
	headerLine := strings.TrimSpace(strings.Join([]string{title, activity, stateBadge, meta}, "  "))
	tabs := m.renderTabs()
	return headerStyle.Render(strings.Join([]string{headerLine, "", tabs}, "\n"))
}

func (m crackstationModel) renderTabs() string {
	tabs := []struct {
		label string
		view  viewMode
	}{
		{label: "Summary", view: viewSummary},
		{label: "Host", view: viewHost},
		{label: "Devices", view: viewDevices},
	}

	parts := make([]string, 0, len(tabs))
	for _, tab := range tabs {
		if m.view == tab.view {
			parts = append(parts, tabActiveStyle.Render(tab.label))
		} else {
			parts = append(parts, tabInactiveStyle.Render(tab.label))
		}
	}
	return tabBarStyle.Render(strings.Join(parts, ""))
}

func (m crackstationModel) renderBody() string {
	if m.view == viewDevices {
		lines := m.renderDeviceLines()
		return boxStyle.Width(m.contentWidth()).Render(strings.Join(lines, "\n"))
	}
	if m.view == viewHost {
		lines := m.renderHostLines()
		return boxStyle.Width(m.contentWidth()).Render(strings.Join(lines, "\n"))
	}

	if m.status == nil {
		return boxStyle.Render("Waiting for status updates ...")
	}

	lines := m.renderSummaryLines()
	detailLines := m.renderDetailLines()
	if len(detailLines) > 0 {
		lines = append(lines, "")
		lines = append(lines, detailLines...)
	}

	return boxStyle.Width(m.contentWidth()).Render(strings.Join(lines, "\n"))
}

func (m crackstationModel) renderSummaryLines() []string {
	now := time.Now()
	return []string{
		formatLine("Name", m.status.GetName()),
		formatLine("Host UUID", m.status.GetHostUUID()),
		formatLine("State", m.status.GetState().String()),
		formatLine("Servers", fmt.Sprintf("%d", countServers(m.crack))),
		formatLine("Last Update", humanizeDuration(now.Sub(m.lastUpdate))+" ago"),
		formatLine("Cracking", crackSummary(m.status, now)),
		formatLine("Syncing", syncSummary(m.status)),
	}
}

func (m crackstationModel) renderDeviceLines() []string {
	if m.crack == nil {
		return []string{formatLine("Devices", "unavailable")}
	}
	info := m.crack.ToProtobuf()
	lines := []string{}

	totalDevices := len(info.GetCUDA()) + len(info.GetOpenCL()) + len(info.GetMetal())
	if totalDevices == 0 {
		lines = append(lines, "", formatLine("Devices", "none detected"))
		return lines
	}

	lines = append(lines, "")
	lines = append(lines, renderCUDADevices(info.GetCUDA())...)
	lines = append(lines, renderOpenCLDevices(info.GetOpenCL())...)
	lines = append(lines, renderMetalDevices(info.GetMetal())...)
	return lines
}

func (m crackstationModel) renderHostLines() []string {
	if m.crack == nil {
		return []string{formatLine("Host", "unavailable")}
	}

	info := m.crack.ToProtobuf()
	lines := []string{
		formatLine("Name", emptyFallback(info.GetName(), "unknown")),
		formatLine("Host UUID", info.GetHostUUID()),
		formatLine("GOOS/GOARCH", fmt.Sprintf("%s/%s", info.GetGOOS(), info.GetGOARCH())),
		formatLine("Hashcat Version", emptyFallback(info.GetHashcatVersion(), "unknown")),
		formatLine("Servers", fmt.Sprintf("%d", countServers(m.crack))),
	}

	if m.status != nil {
		lines = append(lines,
			formatLine("State", m.status.GetState().String()),
			formatLine("Last Update", humanizeDuration(time.Since(m.lastUpdate))+" ago"),
			formatLine("Cracking", crackSummary(m.status, time.Now())),
			formatLine("Syncing", syncSummary(m.status)),
		)
	}

	return lines
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

func (m crackstationModel) viewName() string {
	switch m.view {
	case viewSummary:
		return "summary"
	case viewHost:
		return "host"
	case viewDevices:
		return "devices"
	default:
		return "unknown"
	}
}

func newQuitConfirmForm(value *bool) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Quit crackstation?").
				Affirmative("Yes").
				Negative("No").
				Value(value),
		),
	)
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

func emptyFallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func renderCUDADevices(devices []*clientpb.CUDABackendInfo) []string {
	return renderDeviceSection(
		"CUDA",
		len(devices),
		func(lines []string, index int) []string {
			device := devices[index]
			lines = append(lines, formatLine(fmt.Sprintf("CUDA %d", index), emptyFallback(device.GetName(), "unknown")))
			lines = appendOptionalLine(lines, "Vendor", device.GetVendor())
			lines = appendOptionalLine(lines, "Type", device.GetType())
			lines = appendOptionalLine(lines, "Version", device.GetVersion())
			lines = appendOptionalLine(lines, "CUDA Version", device.GetCUDAVersion())
			lines = appendOptionalIntLine(lines, "Processors", device.GetProcessors())
			lines = appendOptionalClockLine(lines, device.GetClock())
			lines = appendOptionalLine(lines, "Memory Total", device.GetMemoryTotal())
			lines = appendOptionalLine(lines, "Memory Free", device.GetMemoryFree())
			return lines
		},
	)
}

func renderOpenCLDevices(devices []*clientpb.OpenCLBackendInfo) []string {
	return renderDeviceSection(
		"OpenCL",
		len(devices),
		func(lines []string, index int) []string {
			device := devices[index]
			lines = append(lines, formatLine(fmt.Sprintf("OpenCL %d", index), emptyFallback(device.GetName(), "unknown")))
			lines = appendOptionalLine(lines, "Vendor", device.GetVendor())
			lines = appendOptionalLine(lines, "Type", device.GetType())
			lines = appendOptionalLine(lines, "Version", device.GetVersion())
			lines = appendOptionalLine(lines, "OpenCL Version", device.GetOpenCLVersion())
			lines = appendOptionalLine(lines, "Driver Version", device.GetOpenCLDriverVersion())
			lines = appendOptionalIntLine(lines, "Processors", device.GetProcessors())
			lines = appendOptionalClockLine(lines, device.GetClock())
			lines = appendOptionalLine(lines, "Memory Total", device.GetMemoryTotal())
			lines = appendOptionalLine(lines, "Memory Free", device.GetMemoryFree())
			return lines
		},
	)
}

func renderMetalDevices(devices []*clientpb.MetalBackendInfo) []string {
	return renderDeviceSection(
		"Metal",
		len(devices),
		func(lines []string, index int) []string {
			device := devices[index]
			lines = append(lines, formatLine(fmt.Sprintf("Metal %d", index), emptyFallback(device.GetName(), "unknown")))
			lines = appendOptionalLine(lines, "Vendor", device.GetVendor())
			lines = appendOptionalLine(lines, "Type", device.GetType())
			lines = appendOptionalLine(lines, "Version", device.GetVersion())
			lines = appendOptionalLine(lines, "Metal Version", device.GetMetalVersion())
			lines = appendOptionalIntLine(lines, "Processors", device.GetProcessors())
			lines = appendOptionalClockLine(lines, device.GetClock())
			lines = appendOptionalLine(lines, "Memory Total", device.GetMemoryTotal())
			lines = appendOptionalLine(lines, "Memory Free", device.GetMemoryFree())
			return lines
		},
	)
}

func renderDeviceSection(label string, count int, renderDevices func([]string, int) []string) []string {
	lines := []string{titleStyle.Render(fmt.Sprintf("%s Devices (%d)", label, count))}
	if count == 0 {
		lines = append(lines, formatLine(label, "none detected"))
		return append(lines, "")
	}
	for i := 0; i < count; i++ {
		lines = renderDevices(lines, i)
	}
	return append(lines, "")
}

func appendOptionalLine(lines []string, label, value string) []string {
	if value == "" {
		return lines
	}
	return append(lines, formatLine(label, value))
}

func appendOptionalIntLine(lines []string, label string, value int32) []string {
	if value <= 0 {
		return lines
	}
	return append(lines, formatLine(label, fmt.Sprintf("%d", value)))
}

func appendOptionalClockLine(lines []string, clock int32) []string {
	if clock < 0 {
		return lines
	}
	if clock == 0 {
		return lines
	}
	return append(lines, formatLine("Clock (MHz)", fmt.Sprintf("%d", clock)))
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
