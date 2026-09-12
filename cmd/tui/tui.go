package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/charmbracelet/x/ansi"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

type viewMode uint

const (
	viewSummary viewMode = iota
	viewHost
	viewDevices
	viewBenchmarks
	viewFiles
	viewCount

	syncProgressLabelWidth = 12
	maxSyncProgressFiles   = 6
	minSyncProgressWidth   = 6
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
	headerTitleStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230"))
	grpcLabelStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	grpcConnectedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	grpcPartialStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	grpcConnectingStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	grpcDisconnectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	grpcUnavailableStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Bold(true)

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

	confirmBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			Padding(1, 2).
			Width(34)
	confirmTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230"))
	confirmHintStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	confirmActiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("230")).
				Background(lipgloss.Color("62")).
				Padding(0, 1).
				Bold(true)
	confirmInactiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("245")).
				Background(lipgloss.Color("236")).
				Padding(0, 1)
)

type statusMsg *clientpb.CrackstationStatus

type crackstationModel struct {
	crack        *crackstation.Crackstation
	status       *clientpb.CrackstationStatus
	activity     *crackstation.ActivitySnapshot
	statusSub    chan *clientpb.CrackstationStatus
	lastUpdate   time.Time
	spinner      spinner.Model
	syncProgress progress.Model
	view         viewMode
	confirming   bool
	confirmQuit  bool
	benchmarks   map[int32]uint64
	benchErr     error
	fileData     fileViewData
	filePage     int
	devicePage   int
	benchPage    int
	width        int
	height       int
}

func StartTUI(crack *crackstation.Crackstation) error {
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	return normalizeTUIShutdownError(ctx, startTUIContext(ctx, crack))
}

func normalizeTUIShutdownError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	// Bubble Tea wraps every internal failure with ErrProgramKilled, including
	// panics. Suppress it only when our signal context actually initiated the
	// shutdown; preserve unrelated renderer/runtime failures for the CLI.
	if ctx != nil && ctx.Err() != nil && errors.Is(err, tea.ErrProgramKilled) {
		return nil
	}
	if errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	return err
}

func startTUIContext(ctx context.Context, crack *crackstation.Crackstation, options ...tea.ProgramOption) error {
	go crack.Start()
	defer crack.Stop()

	statusSub := crack.StatusBroker.Subscribe()
	defer crack.StatusBroker.Unsubscribe(statusSub)

	// The process-level signal context owns shutdown so every exit path reaches
	// the synchronous Crackstation.Stop barrier. Bubble Tea's independent signal
	// handler is disabled to avoid racing that lifecycle.
	options = append(options, tea.WithContext(ctx), tea.WithoutSignalHandler())
	p := tea.NewProgram(newModel(crack, statusSub), options...)
	_, err := p.Run()
	return err
}

func StartLogOnly(crack *crackstation.Crackstation, out io.Writer) {
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	startLogOnlyContext(ctx, crack, out)
}

func startLogOnlyContext(ctx context.Context, crack *crackstation.Crackstation, out io.Writer) {
	go crack.Start()
	defer crack.Stop()

	statusSub := crack.StatusBroker.Subscribe()
	defer crack.StatusBroker.Unsubscribe(statusSub)

	var lastKey string
	for {
		select {
		case <-ctx.Done():
			return
		case status, ok := <-statusSub:
			if !ok {
				return
			}
			key := statusKey(status)
			if key == lastKey {
				continue
			}
			fmt.Fprintln(out, formatStatusLine(status, time.Now()))
			lastKey = key
		}
	}
}

func newModel(crack *crackstation.Crackstation, statusSub chan *clientpb.CrackstationStatus) crackstationModel {
	spin := spinner.New()
	spin.Spinner = spinner.Line
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	var benchmarks map[int32]uint64
	var benchErr error
	if crack != nil {
		benchmarks, benchErr = crack.LoadBenchmarkResults()
	}
	model := crackstationModel{
		crack:        crack,
		statusSub:    statusSub,
		lastUpdate:   time.Now(),
		spinner:      spin,
		syncProgress: newSyncProgress(),
		view:         viewSummary,
		benchmarks:   benchmarks,
		benchErr:     benchErr,
	}
	if crack != nil {
		model.status = crack.Status()
		model.activity = crack.Activity()
		model.fileData = collectFileViewData(crack.FileInventories())
	}
	return model
}

func newSyncProgress() progress.Model {
	bar := progress.New(progress.WithColors(lipgloss.Color("69")))
	bar.PercentageStyle = valueStyle
	return bar
}

func (m crackstationModel) Init() tea.Cmd {
	return tea.Batch(tea.Cmd(m.spinner.Tick), waitForStatus(m.statusSub))
}

func (m crackstationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		if m.confirming {
			switch msg.String() {
			case "left", "h":
				m.confirmQuit = true
			case "right", "l":
				m.confirmQuit = false
			case "tab", "shift+tab", "space":
				m.confirmQuit = !m.confirmQuit
			case "y":
				return m, tea.Quit
			case "n", "esc":
				m.confirming = false
				m.confirmQuit = false
			case "enter":
				if m.confirmQuit {
					return m, tea.Quit
				}
				m.confirming = false
				m.confirmQuit = false
			}
			return m, nil
		}

		switch msg.String() {
		case "ctrl+c", "q":
			m.confirming = true
			m.confirmQuit = false
			return m, nil
		case "tab":
			m.view = (m.view + 1) % viewCount
		case "left":
			if m.view == viewFiles {
				pages := m.filePageCount()
				if pages > 0 {
					m.filePage = (m.filePage - 1 + pages) % pages
				}
			}
			if m.view == viewDevices {
				pages := m.devicePageCount()
				if pages > 0 {
					m.devicePage = (m.devicePage - 1 + pages) % pages
				}
			}
			if m.view == viewBenchmarks {
				pages := m.benchPageCount()
				if pages > 0 {
					m.benchPage = (m.benchPage - 1 + pages) % pages
				}
			}
		case "right":
			if m.view == viewFiles {
				pages := m.filePageCount()
				if pages > 0 {
					m.filePage = (m.filePage + 1) % pages
				}
			}
			if m.view == viewDevices {
				pages := m.devicePageCount()
				if pages > 0 {
					m.devicePage = (m.devicePage + 1) % pages
				}
			}
			if m.view == viewBenchmarks {
				pages := m.benchPageCount()
				if pages > 0 {
					m.benchPage = (m.benchPage + 1) % pages
				}
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.filePage = m.clampFilePage(m.filePage)
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case statusMsg:
		previousActivity := m.activity
		m.status = (*clientpb.CrackstationStatus)(msg)
		if m.crack != nil {
			m.activity = m.crack.Activity()
			m.fileData = collectFileViewData(m.crack.FileInventories())
			m.filePage = m.clampFilePage(m.filePage)
		}
		if benchmarkActivityEnded(previousActivity, m.activity) && m.crack != nil {
			benchmarks, err := m.crack.LoadBenchmarkResults()
			if err == nil {
				m.benchmarks = benchmarks
				m.benchErr = nil
				m.benchPage = 0
			} else if len(m.benchmarks) == 0 {
				m.benchErr = err
			}
		}
		m.lastUpdate = time.Now()
		return m, waitForStatus(m.statusSub)
	}
	return m, nil
}

func benchmarkActivityEnded(previous, current *crackstation.ActivitySnapshot) bool {
	return previous != nil && previous.Kind == crackstation.ActivityBenchmarking &&
		(current == nil || current.Kind != crackstation.ActivityBenchmarking)
}

func (m crackstationModel) View() tea.View {
	content := m.renderMainView()
	if m.confirming {
		content = m.renderConfirmView()
	}
	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

func (m crackstationModel) renderMainView() string {
	header := m.renderHeader()
	body := m.renderBody()
	footer := helpStyle.Render(ansi.Truncate(m.footerText(), m.terminalWidth(), "…"))
	return strings.Join([]string{header, body, footer}, "\n\n")
}

func (m crackstationModel) renderConfirmView() string {
	buttonStyle := confirmInactiveStyle
	if m.confirmQuit {
		buttonStyle = confirmActiveStyle
	}
	noStyle := confirmInactiveStyle
	if !m.confirmQuit {
		noStyle = confirmActiveStyle
	}

	body := confirmBoxStyle.Render(strings.Join([]string{
		confirmTitleStyle.Render("Quit crackstation?"),
		"",
		"Use \u2190/\u2192 or tab to choose.",
		"",
		lipgloss.JoinHorizontal(lipgloss.Left, buttonStyle.Render("Yes"), " ", noStyle.Render("No")),
		"",
		confirmHintStyle.Render("enter: confirm  esc: cancel"),
	}, "\n"))

	if m.width > 0 && m.height > 0 {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, body)
	}
	return body
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
	meta := m.renderGRPCStatus()
	available := m.terminalWidth() - 2
	if available < 1 {
		available = 1
	}
	headerLine := ansi.Truncate(strings.TrimSpace(strings.Join([]string{title, activity, stateBadge, meta}, "  ")), available, "…")
	tabs := ansi.Truncate(m.renderTabs(), available, "…")
	return headerStyle.Render(strings.Join([]string{headerLine, "", tabs}, "\n"))
}

func (m crackstationModel) footerText() string {
	hint := ""
	if m.view == viewFiles || m.view == viewDevices || m.view == viewBenchmarks {
		hint = "  \u2190/\u2192: page"
	}
	return fmt.Sprintf("q: quit  tab: next view  view: %s%s", m.viewName(), hint)
}

func (m crackstationModel) devicePageCount() int {
	if m.crack == nil {
		return 0
	}
	sections := deviceSections(m.crack.ToProtobuf(), len(m.crack.HIPBackendInfo()))
	if len(sections) == 0 {
		return 0
	}
	return len(sections)
}

func (m crackstationModel) benchPageCount() int {
	if m.benchErr != nil || len(m.benchmarks) == 0 {
		return 0
	}
	pageSize := m.benchPageSize(len(m.benchmarks))
	if pageSize <= 0 {
		return 0
	}
	return (len(m.benchmarks) + pageSize - 1) / pageSize
}

func (m crackstationModel) benchPageSize(total int) int {
	if total <= 0 {
		return 0
	}
	pageSize := total
	if m.height > 0 {
		usable := m.height - 12
		if usable < 5 {
			usable = 5
		}
		if pageSize > usable {
			pageSize = usable
		}
	}
	if pageSize < 1 {
		return 1
	}
	return pageSize
}

func (m crackstationModel) renderTabs() string {
	tabs := []struct {
		label string
		view  viewMode
	}{
		{label: "Summary", view: viewSummary},
		{label: "Host", view: viewHost},
		{label: "Devices", view: viewDevices},
		{label: "Benchmarks", view: viewBenchmarks},
		{label: "Files", view: viewFiles},
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
	if m.view == viewFiles {
		return m.renderBox(m.renderFileLines())
	}
	if m.view == viewDevices {
		lines := m.renderDeviceLines()
		return m.renderBox(lines)
	}
	if m.view == viewHost {
		lines := m.renderHostLines()
		return m.renderBox(lines)
	}
	if m.view == viewBenchmarks {
		lines := m.renderBenchmarkLines()
		return m.renderBox(lines)
	}

	if m.status == nil {
		return boxStyle.Render("Waiting for status updates ...")
	}

	var lines []string
	if m.activity != nil || (m.status.GetIsSyncing() && m.status.GetSyncing() != nil) {
		// Put live work first so the useful telemetry remains visible even in a
		// short terminal. The static host summary is still available below and
		// in the Host tab.
		lines = m.renderDetailLines()
		lines = append(lines, "")
		lines = append(lines, m.renderActiveHostLine(time.Now()))
	} else {
		lines = m.renderSummaryLines()
		detailLines := m.renderDetailLines()
		if len(detailLines) > 0 {
			lines = append(lines, "")
			lines = append(lines, detailLines...)
		}
	}

	return m.renderBox(lines)
}

func (m crackstationModel) renderActiveHostLine(now time.Time) string {
	age := now.Sub(m.lastUpdate)
	if age < 0 {
		age = 0
	}
	return formatLine("Host", fmt.Sprintf("%s | %s | %d servers | update %s ago",
		emptyFallback(m.status.GetName(), "unknown"),
		m.status.GetState().String(),
		countServers(m.crack),
		humanizeDuration(age),
	))
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

	sections := deviceSections(info, len(m.crack.HIPBackendInfo()))
	if len(sections) == 0 {
		lines = append(lines, "", formatLine("Devices", "none detected"))
		return lines
	}

	page := m.devicePage
	if page < 0 {
		page = 0
	}
	if page >= len(sections) {
		page = len(sections) - 1
	}

	section := sections[page]
	lines = append(lines, formatLine("Page", fmt.Sprintf("%d/%d", page+1, len(sections))))
	lines = append(lines, "")
	switch section.kind {
	case deviceCUDA:
		lines = append(lines, renderCUDADevices(info.GetCUDA())...)
	case deviceHIP:
		lines = append(lines, renderHIPDevices(m.crack.HIPBackendInfo())...)
	case deviceMetal:
		lines = append(lines, renderMetalDevices(info.GetMetal())...)
	case deviceOpenCL:
		lines = append(lines, renderOpenCLDevices(info.GetOpenCL())...)
	}

	if len(lines) == 0 {
		lines = append(lines, formatLine(section.label, "none detected"))
	}

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
		formatLine("OS/Arch", fmt.Sprintf("%s/%s", info.GetGOOS(), info.GetGOARCH())),
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

func (m crackstationModel) renderBenchmarkLines() []string {
	if m.benchErr != nil {
		return []string{
			formatLine("Benchmarks", "unavailable"),
			formatLine("Error", m.benchErr.Error()),
		}
	}
	if len(m.benchmarks) == 0 {
		return []string{formatLine("Benchmarks", "no data")}
	}

	keys := make([]int, 0, len(m.benchmarks))
	for key := range m.benchmarks {
		keys = append(keys, int(key))
	}
	sort.Ints(keys)

	pageSize := m.benchPageSize(len(keys))

	totalPages := m.benchPageCount()
	page := m.benchPage
	if page < 0 {
		page = 0
	}
	if page >= totalPages {
		page = totalPages - 1
	}

	lines := []string{
		formatLine("Benchmarks", fmt.Sprintf("%d modes", len(keys))),
		formatLine("Page", fmt.Sprintf("%d/%d", page+1, totalPages)),
		"",
	}

	start := page * pageSize
	end := start + pageSize
	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		hashMode := int32(key)
		label := fmt.Sprintf("%s (%d)", hashTypeLabel(hashMode), hashMode)
		lines = append(lines, formatLine(label, humanizeHashRate(m.benchmarks[hashMode])))
	}

	return lines
}

func (m crackstationModel) renderDetailLines() []string {
	lines := m.renderSyncLines()
	activityLines := m.renderActivityLines(time.Now())
	if len(activityLines) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, activityLines...)
	}
	return lines
}

func (m crackstationModel) renderSyncLines() []string {
	if m.status == nil || !m.status.GetIsSyncing() || m.status.GetSyncing() == nil {
		return nil
	}

	progress := m.status.GetSyncing().GetProgress()
	if len(progress) == 0 {
		return []string{
			titleStyle.Render("File Synchronization"),
			formatLine("Sync Progress", "No file progress reported"),
		}
	}

	keys := make([]string, 0, len(progress))
	for key := range progress {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := []string{
		titleStyle.Render(fmt.Sprintf(
			"File Synchronization (%d files @ %s)",
			len(keys),
			humanizeRate(m.status.GetSyncing().GetSpeed()),
		)),
		m.renderSyncProgressLine("Overall", averageProgress(progress)),
	}
	for i, key := range keys {
		if i >= maxSyncProgressFiles {
			lines = append(lines, formatLine("...", fmt.Sprintf("%d more", len(keys)-maxSyncProgressFiles)))
			break
		}
		lines = append(lines, m.renderSyncProgressLine(key, progress[key]))
	}
	return lines
}

func (m crackstationModel) renderSyncProgressLine(label string, value float32) string {
	percent := normalizedProgress(value)
	shortLabel := truncateString(label, syncProgressLabelWidth)
	paddedLabel := fmt.Sprintf("%-*s", syncProgressLabelWidth+1, shortLabel+":")
	prefix := labelStyle.Render(paddedLabel) + " "
	barWidth := m.bodyLineWidth() - ansi.StringWidth(prefix)
	if barWidth < minSyncProgressWidth {
		percentage := fmt.Sprintf("%.0f%%", percent*100)
		labelWidth := m.bodyLineWidth() - ansi.StringWidth(percentage) - 2
		if labelWidth < 1 {
			labelWidth = 1
		}
		return formatLine(truncateString(label, labelWidth), percentage)
	}

	bar := m.syncProgress
	if bar.Width() == 0 {
		bar = newSyncProgress()
	}
	bar.SetWidth(barWidth)
	return prefix + bar.ViewAs(percent)
}

func (m crackstationModel) renderActivityLines(now time.Time) []string {
	activity := m.activity
	if activity == nil {
		return nil
	}

	lines := []string{titleStyle.Render("Running Job")}
	jobDetails := []string{activity.Kind.String()}
	if activity.JobID != "" {
		jobDetails = append(jobDetails, activity.JobID)
	}
	if !activity.StartedAt.IsZero() {
		elapsed := now.Sub(activity.StartedAt)
		if elapsed < 0 {
			elapsed = 0
		}
		jobDetails = append(jobDetails, "elapsed "+humanizeDuration(elapsed))
	}
	if activity.Attempt > 1 {
		jobDetails = append(jobDetails, fmt.Sprintf("attempt %d", activity.Attempt))
	}
	if phase := activity.Phase.String(); phase != "" {
		jobDetails = append(jobDetails, phase)
	}
	lines = append(lines, formatLine("Job", strings.Join(jobDetails, " | ")))

	switch activity.Kind {
	case crackstation.ActivityBenchmarking:
		return append(lines, renderBenchmarkActivity(activity.BenchmarkProgress)...)
	case crackstation.ActivityCracking:
		return append(lines, m.renderCrackActivity(activity, now)...)
	case crackstation.ActivityKeyspace:
		return append(lines,
			formatLine("Work", activityWorkDescription(activity)),
			formatLine("Keyspace", "calculating candidate count; live rate and hardware metrics are not emitted for this probe"),
		)
	default:
		return lines
	}
}

func (m crackstationModel) renderCrackActivity(activity *crackstation.ActivitySnapshot, now time.Time) []string {
	lines := []string{formatLine("Work", activityWorkDescription(activity))}
	if activity.ShardSkip > 0 || activity.ShardLimit > 0 {
		lines = append(lines, formatLine("Shard", fmt.Sprintf("skip %s, limit %s", humanizeCount(activity.ShardSkip), humanizeCount(activity.ShardLimit))))
	}

	status := activity.HashcatStatus
	if status == nil {
		return append(lines, formatLine("Hashcat", "waiting for first status sample"))
	}
	hashcatDetails := []string{status.StateName()}
	if status.Progress.Total > 0 {
		percent := float64(status.Progress.Current) / float64(status.Progress.Total) * 100
		if percent > 100 {
			percent = 100
		}
		hashcatDetails = append(hashcatDetails, fmt.Sprintf("%.2f%% (%s / %s)", percent, humanizeCount(status.Progress.Current), humanizeCount(status.Progress.Total)))
	}
	if !activity.TelemetryAt.IsZero() {
		age := now.Sub(activity.TelemetryAt)
		if age < 0 {
			age = 0
		}
		if age >= 3*time.Second {
			hashcatDetails = append(hashcatDetails, "telemetry "+humanizeDuration(age)+" old")
		}
	}
	lines = append(lines, formatLine("Hashcat", strings.Join(hashcatDetails, " | ")))
	performance := []string{}
	if speed := status.TotalSpeed(); speed > 0 {
		performance = append(performance, humanizeHashRate(speed))
	} else if len(status.Devices) == 0 {
		performance = append(performance, "waiting for device metrics")
	} else {
		performance = append(performance, "measuring...")
	}
	if eta, ok := statusETA(status, now); ok {
		performance = append(performance, fmt.Sprintf("ETA %s (%s)", humanizeDuration(eta.Sub(now)), eta.Format("15:04:05")))
	}
	lines = append(lines, formatLine("Performance", strings.Join(performance, " | ")))
	results := []string{}
	if status.RecoveredHashes.Total > 0 {
		results = append(results, fmt.Sprintf("%d/%d hashes, %d/%d salts",
			status.RecoveredHashes.Current,
			status.RecoveredHashes.Total,
			status.RecoveredSalts.Current,
			status.RecoveredSalts.Total,
		))
	}
	results = append(results, humanizeCount(status.Rejected)+" rejected")
	lines = append(lines, formatLine("Results", strings.Join(results, " | ")))

	if len(status.Devices) > 0 && !hasHardwareMetrics(status.Devices) {
		lines = append(lines, formatLine("Hardware", "temperature/utilization unavailable"))
	}
	deviceLimit := len(status.Devices)
	if deviceLimit > 4 {
		deviceLimit = 4
	}
	for _, device := range status.Devices[:deviceLimit] {
		lines = append(lines, renderActiveDevice(device)...)
	}
	if remaining := len(status.Devices) - deviceLimit; remaining > 0 {
		lines = append(lines, formatLine("Devices", fmt.Sprintf("%d more", remaining)))
	}
	return lines
}

func activityWorkDescription(activity *crackstation.ActivitySnapshot) string {
	work := []string{}
	if activity.HasHashMode {
		work = append(work, fmt.Sprintf("%s (%d)", hashTypeLabel(activity.HashMode), activity.HashMode))
	}
	work = append(work, attackModeLabel(activity.AttackMode))
	if activity.HashCount > 0 {
		work = append(work, fmt.Sprintf("%d hashes", activity.HashCount))
	}
	return strings.Join(work, " | ")
}

func renderBenchmarkActivity(progress *hashcat.BenchmarkProgress) []string {
	if progress == nil {
		return []string{
			formatLine("Benchmark", "initializing"),
			formatLine("Hardware Metrics", "temperature/utilization unavailable in benchmark mode"),
		}
	}

	lines := []string{}
	if progress.HashName != "" || progress.HashMode != 0 {
		lines = append(lines, formatLine("Current Mode", benchmarkModeLabel(progress.HashMode, progress.HashName)))
	} else {
		lines = append(lines, formatLine("Current Mode", "waiting for Hashcat"))
	}
	if progress.TotalModes > 0 {
		lines = append(lines, formatLine("Mode Progress", fmt.Sprintf("%d/%d complete", progress.CompletedModes, progress.TotalModes)))
	} else {
		lines = append(lines, formatLine("Mode Progress", fmt.Sprintf("%d complete", progress.CompletedModes)))
	}
	if progress.Speed > 0 {
		result := humanizeHashRate(progress.Speed)
		if !progress.ModeComplete {
			result += " (partial)"
		}
		lines = append(lines, formatLine("Current Result", result))
	} else {
		lines = append(lines, formatLine("Current Result", "measuring..."))
	}

	lastSpeed := progress.LastSpeed
	lastMode := progress.LastHashMode
	lastName := progress.LastHashName
	lastDevices := progress.LastDeviceSpeeds
	if lastSpeed > 0 && (lastMode != progress.HashMode || progress.Speed == 0) {
		lines = append(lines, formatLine("Latest Result", fmt.Sprintf("%s @ %s", benchmarkModeLabel(lastMode, lastName), humanizeHashRate(lastSpeed))))
	}
	lines = append(lines, formatLine("Hardware Metrics", "temperature/utilization unavailable in benchmark mode"))
	devices := progress.DeviceSpeeds
	if len(devices) == 0 {
		devices = lastDevices
	}
	deviceLimit := len(devices)
	if deviceLimit > 4 {
		deviceLimit = 4
	}
	for _, device := range devices[:deviceLimit] {
		lines = append(lines, formatLine(fmt.Sprintf("Device #%d", device.Device), humanizeHashRate(device.Speed)))
	}
	if remaining := len(devices) - deviceLimit; remaining > 0 {
		lines = append(lines, formatLine("Devices", fmt.Sprintf("%d more", remaining)))
	}
	return lines
}

func hasHardwareMetrics(devices []hashcat.DeviceStatus) bool {
	for _, device := range devices {
		if device.Temp >= 0 || device.Util >= 0 || device.FanSpeed >= 0 || device.CoreSpeed >= 0 || device.MemorySpeed >= 0 || device.BusLanes > 0 || device.Power >= 0 {
			return true
		}
	}
	return false
}

func benchmarkModeLabel(mode int32, name string) string {
	if name == "" {
		return fmt.Sprintf("%s (%d)", hashTypeLabel(mode), mode)
	}
	return fmt.Sprintf("%s (%d)", name, mode)
}

func renderActiveDevice(device hashcat.DeviceStatus) []string {
	name := emptyFallback(device.Name, emptyFallback(device.Type, "unknown"))
	metrics := []string{humanizeHashRate(device.Speed)}
	if device.Temp >= 0 {
		metrics = append(metrics, fmt.Sprintf("%d°C", device.Temp))
	}
	if device.Util >= 0 {
		metrics = append(metrics, fmt.Sprintf("%d%% util", device.Util))
	}
	if device.FanSpeed >= 0 {
		metrics = append(metrics, fmt.Sprintf("%d%% fan", device.FanSpeed))
	}
	if device.Power >= 0 {
		metrics = append(metrics, fmt.Sprintf("%.1f W", float64(device.Power)/1000))
	}
	lines := []string{formatLine(fmt.Sprintf("Device #%d", device.ID), fmt.Sprintf("%s | %s", truncateString(name, 32), strings.Join(metrics, " | ")))}

	clocks := []string{}
	if device.CoreSpeed >= 0 {
		clocks = append(clocks, fmt.Sprintf("core %d MHz", device.CoreSpeed))
	}
	if device.MemorySpeed >= 0 {
		clocks = append(clocks, fmt.Sprintf("memory %d MHz", device.MemorySpeed))
	}
	if device.BusLanes > 0 {
		clocks = append(clocks, fmt.Sprintf("PCIe x%d", device.BusLanes))
	}
	if len(clocks) > 0 {
		lines = append(lines, formatLine(fmt.Sprintf("Device #%d Clocks", device.ID), strings.Join(clocks, " | ")))
	}
	return lines
}

func statusETA(status *hashcat.Status, now time.Time) (time.Time, bool) {
	if status == nil || status.EstimatedStop <= 1 || status.EstimatedStop > math.MaxInt64 {
		return time.Time{}, false
	}
	eta := time.Unix(int64(status.EstimatedStop), 0)
	return eta, eta.After(now)
}

func (m crackstationModel) renderBox(lines []string) string {
	if maxLines := m.bodyContentHeight(); maxLines > 0 && len(lines) > maxLines {
		omitted := len(lines) - maxLines + 1
		if maxLines == 1 {
			lines = []string{formatLine("...", fmt.Sprintf("%d more lines", omitted))}
		} else {
			lines = append(append([]string(nil), lines[:maxLines-1]...), formatLine("...", fmt.Sprintf("%d more lines", omitted)))
		}
	}
	width := m.contentWidth()
	lineWidth := m.bodyLineWidth()
	bounded := make([]string, len(lines))
	for index, line := range lines {
		bounded[index] = ansi.Truncate(line, lineWidth, "…")
	}
	return boxStyle.Width(width).Render(strings.Join(bounded, "\n"))
}

func (m crackstationModel) bodyContentHeight() int {
	if m.height <= 0 {
		return 0
	}
	// Reserve the header, footer, body border, and the blank rows inserted by
	// renderMainView. Lip Gloss keeps one additional terminal row for the body
	// border at constrained heights.
	available := m.height - 9
	if available < 1 {
		return 1
	}
	return available
}

func (m crackstationModel) terminalWidth() int {
	if m.width <= 0 {
		return 80
	}
	return m.width
}

func (m crackstationModel) contentWidth() int {
	width := m.terminalWidth()
	if width <= 4 {
		return 1
	}
	return width - 4
}

func (m crackstationModel) bodyLineWidth() int {
	width := m.contentWidth() - boxStyle.GetHorizontalFrameSize()
	if width < 1 {
		return 1
	}
	return width
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
	case viewFiles:
		return "files"
	case viewHost:
		return "host"
	case viewDevices:
		return "devices"
	case viewBenchmarks:
		return "benchmarks"
	default:
		return "unknown"
	}
}

func (m crackstationModel) grpcStatus() string {
	if m.crack == nil || m.crack.Servers == nil {
		return "gRPC: unavailable"
	}
	total, connected, connecting := countServerStates(m.crack)
	if total == 0 {
		return "gRPC: none"
	}
	pending, next := reconnectSummary(m.crack, time.Now())
	if connected == total {
		return fmt.Sprintf("gRPC: connected (%d)", connected)
	}
	if connected > 0 {
		if pending > 0 && next > 0 {
			return fmt.Sprintf("gRPC: partial (%d/%d, retry in %s)", connected, total, humanizeDuration(next))
		}
		return fmt.Sprintf("gRPC: partial (%d/%d)", connected, total)
	}
	if connecting > 0 {
		if pending > 0 && next > 0 {
			return fmt.Sprintf("gRPC: connecting (%d, retry in %s)", connecting, humanizeDuration(next))
		}
		return fmt.Sprintf("gRPC: connecting (%d)", connecting)
	}
	if pending > 0 && next > 0 {
		return fmt.Sprintf("gRPC: reconnecting in %s (%d)", humanizeDuration(next), pending)
	}
	return fmt.Sprintf("gRPC: disconnected (%d)", total)
}

func (m crackstationModel) renderGRPCStatus() string {
	label := grpcLabelStyle.Render("gRPC:")
	if m.crack == nil || m.crack.Servers == nil {
		return strings.Join([]string{label, grpcUnavailableStyle.Render("unavailable")}, " ")
	}
	total, connected, connecting := countServerStates(m.crack)
	if total == 0 {
		return strings.Join([]string{label, grpcUnavailableStyle.Render("none")}, " ")
	}
	pending, next := reconnectSummary(m.crack, time.Now())
	if connected == total {
		return strings.Join([]string{label, grpcConnectedStyle.Render(fmt.Sprintf("connected (%d)", connected))}, " ")
	}
	if connected > 0 {
		if pending > 0 && next > 0 {
			return strings.Join([]string{label, grpcPartialStyle.Render(fmt.Sprintf("partial (%d/%d, retry in %s)", connected, total, humanizeDuration(next)))}, " ")
		}
		return strings.Join([]string{label, grpcPartialStyle.Render(fmt.Sprintf("partial (%d/%d)", connected, total))}, " ")
	}
	if connecting > 0 {
		if pending > 0 && next > 0 {
			return strings.Join([]string{label, grpcConnectingStyle.Render(fmt.Sprintf("connecting (%d, retry in %s)", connecting, humanizeDuration(next)))}, " ")
		}
		return strings.Join([]string{label, grpcConnectingStyle.Render(fmt.Sprintf("connecting (%d)", connecting))}, " ")
	}
	if pending > 0 && next > 0 {
		return strings.Join([]string{label, grpcConnectingStyle.Render(fmt.Sprintf("reconnecting in %s (%d)", humanizeDuration(next), pending))}, " ")
	}
	return strings.Join([]string{label, grpcDisconnectedStyle.Render(fmt.Sprintf("disconnected (%d)", total))}, " ")
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

func countServerStates(crack *crackstation.Crackstation) (int, int, int) {
	if crack == nil || crack.Servers == nil {
		return 0, 0, 0
	}
	total := 0
	connected := 0
	connecting := 0
	crack.Servers.Range(func(_, value interface{}) bool {
		total++
		server, ok := value.(*crackstation.SliverServer)
		if !ok || server == nil {
			return true
		}
		switch server.ConnectionState() {
		case crackstation.CONNECTED:
			connected++
		case crackstation.CONNECTING:
			connecting++
		}
		return true
	})
	return total, connected, connecting
}

func reconnectSummary(crack *crackstation.Crackstation, now time.Time) (int, time.Duration) {
	if crack == nil || crack.Servers == nil {
		return 0, 0
	}
	pending := 0
	var next time.Duration
	crack.Servers.Range(func(_, value interface{}) bool {
		server, ok := value.(*crackstation.SliverServer)
		if !ok || server == nil || server.ConnectionState() != crackstation.DISCONNECTED {
			return true
		}
		remaining := server.ReconnectIn(now)
		if remaining <= 0 {
			return true
		}
		pending++
		if next == 0 || remaining < next {
			next = remaining
		}
		return true
	})
	return pending, next
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

func statusKey(status *clientpb.CrackstationStatus) string {
	if status == nil {
		return "status unavailable"
	}
	return fmt.Sprintf(
		"name=%s state=%s crack=%s sync=%s",
		status.GetName(),
		status.GetState().String(),
		crackSummary(status, time.Time{}),
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
	var total float64
	for _, val := range progress {
		total += normalizedProgress(val)
	}
	return float32(total / float64(len(progress)))
}

func normalizedProgress(value float32) float64 {
	percent := float64(value)
	if math.IsNaN(percent) || math.IsInf(percent, 0) {
		return 0
	}
	return math.Max(0, math.Min(1, percent))
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

func hashTypeLabel(hashMode int32) string {
	if name, ok := clientpb.HashType_name[hashMode]; ok {
		return strings.ReplaceAll(name, "_", " ")
	}
	return fmt.Sprintf("Hash Mode %d", hashMode)
}

func attackModeLabel(mode clientpb.CrackAttackMode) string {
	switch mode {
	case clientpb.CrackAttackMode_STRAIGHT:
		return "Straight"
	case clientpb.CrackAttackMode_COMBINATION:
		return "Combination"
	case clientpb.CrackAttackMode_BRUTEFORCE:
		return "Brute force"
	case clientpb.CrackAttackMode_HYBRID_WORDLIST_MASK:
		return "Hybrid wordlist + mask"
	case clientpb.CrackAttackMode_HYBRID_MASK_WORDLIST:
		return "Hybrid mask + wordlist"
	case clientpb.CrackAttackMode_ASSOCIATION:
		return "Association"
	case clientpb.CrackAttackMode_NO_ATTACK:
		return "No attack"
	default:
		return strings.ReplaceAll(mode.String(), "_", " ")
	}
}

func humanizeCount(value uint64) string {
	if value < 1000 {
		return fmt.Sprintf("%d", value)
	}
	suffixes := []string{"k", "M", "G", "T", "P", "E"}
	scaled := float64(value)
	exp := 0
	for scaled >= 1000 && exp < len(suffixes) {
		scaled /= 1000
		exp++
	}
	return fmt.Sprintf("%.2f%s", scaled, suffixes[exp-1])
}

func humanizeHashRate(rate uint64) string {
	const unit = 1000
	if rate < unit {
		return fmt.Sprintf("%d H/s", rate)
	}
	value := float64(rate)
	exp := 0
	for value >= unit && exp < 5 {
		value /= unit
		exp++
	}
	suffixes := []string{"kH/s", "MH/s", "GH/s", "TH/s", "PH/s"}
	if exp == 0 {
		return fmt.Sprintf("%d H/s", rate)
	}
	if exp > len(suffixes) {
		exp = len(suffixes)
	}
	return fmt.Sprintf("%.2f %s", value, suffixes[exp-1])
}

type deviceSectionKind int

const (
	deviceCUDA deviceSectionKind = iota
	deviceHIP
	deviceMetal
	deviceOpenCL
)

type deviceSection struct {
	label string
	count int
	kind  deviceSectionKind
}

func deviceSections(info *clientpb.Crackstation, hipCount int) []deviceSection {
	sections := []deviceSection{
		{label: "CUDA", count: len(info.GetCUDA()), kind: deviceCUDA},
		{label: "HIP", count: hipCount, kind: deviceHIP},
		{label: "Metal", count: len(info.GetMetal()), kind: deviceMetal},
		{label: "OpenCL", count: len(info.GetOpenCL()), kind: deviceOpenCL},
	}

	primary := []deviceSection{sections[0], sections[1], sections[2]}
	sort.SliceStable(primary, func(i, j int) bool {
		if primary[i].count == primary[j].count {
			return primary[i].label < primary[j].label
		}
		return primary[i].count > primary[j].count
	})

	ordered := []deviceSection{primary[0], primary[1], primary[2], sections[3]}
	return ordered
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

func renderHIPDevices(devices []*hashcat.HIPBackendInfo) []string {
	return renderDeviceSection(
		"HIP",
		len(devices),
		func(lines []string, index int) []string {
			device := devices[index]
			lines = append(lines, formatLine(fmt.Sprintf("HIP %d", index), emptyFallback(device.Name, "unknown")))
			lines = appendOptionalLine(lines, "Vendor", device.Vendor)
			lines = appendOptionalLine(lines, "Type", device.Type)
			lines = appendOptionalLine(lines, "Version", device.Version)
			lines = appendOptionalLine(lines, "HIP Version", device.HIPVersion)
			lines = appendOptionalIntLine(lines, "Processors", device.Processors)
			lines = appendOptionalClockLine(lines, device.Clock)
			lines = appendOptionalLine(lines, "Memory Total", device.MemoryTotal)
			lines = appendOptionalLine(lines, "Memory Free", device.MemoryFree)
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
	return ansi.Truncate(value, max, "…")
}
