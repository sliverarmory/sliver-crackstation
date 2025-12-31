package tui

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/timer"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
	"golang.org/x/term"
)

/*
This example assumes an existing understanding of commands and messages. If you
haven't already read our tutorials on the basics of Bubble Tea and working
with commands, we recommend reading those first.

Find them at:
https://github.com/charmbracelet/bubbletea/tree/master/tutorials/commands
https://github.com/charmbracelet/bubbletea/tree/master/tutorials/basics
*/

func StartTUI(crack *crackstation.Crackstation) {
	go crack.Start()
	defer crack.Stop()
	p := tea.NewProgram(newModel(crack))
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

// sessionState is used to track which model is focused
type sessionState uint

const (
	defaultTime = time.Minute

	timerView sessionState = iota
	spinnerView
)

var (
	// Available spinners
	spinners = []spinner.Spinner{
		spinner.Line,
		spinner.Dot,
		spinner.MiniDot,
		spinner.Jump,
		spinner.Pulse,
		spinner.Points,
		spinner.Globe,
		spinner.Moon,
		spinner.Monkey,
	}
	modelStyle = lipgloss.NewStyle().
			Width(25).
			Height(5).
			Align(lipgloss.Center, lipgloss.Center).
			BorderStyle(lipgloss.HiddenBorder())
	crackstationStyle = lipgloss.NewStyle().
		// Width(25).
		// Height(5).
		Align(lipgloss.Center, lipgloss.Center).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("69"))

	statusNugget = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Padding(0, 1)
	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#343433", Dark: "#C1C6B2"}).
			Background(lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#353533"})
	statusStyle = lipgloss.NewStyle().
			Inherit(statusBarStyle).
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#FF5F87")).
			Padding(0, 1).
			MarginRight(1)
	encodingStyle = statusNugget.Copy().
			Background(lipgloss.Color("#A550DF")).
			Align(lipgloss.Right)
	statusText    = lipgloss.NewStyle().Inherit(statusBarStyle)
	fishCakeStyle = statusNugget.Copy().Background(lipgloss.Color("#6124DF"))

	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

type crackstationModel struct {
	c *crackstation.Crackstation

	state   sessionState
	timer   timer.Model
	spinner spinner.Model
	index   int
}

func newModel(crack *crackstation.Crackstation) crackstationModel {
	m := crackstationModel{state: timerView, c: crack}
	m.timer = timer.New(time.Minute)
	m.spinner = spinner.New()
	return m
}

func (m crackstationModel) Init() tea.Cmd {
	return tea.Batch(m.timer.Init(), m.spinner.Tick)
}

func (m crackstationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			if m.state == timerView {
				m.state = spinnerView
			} else {
				m.state = timerView
			}

		}
		switch m.state {
		// update whichever model is focused
		case spinnerView:
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		default:
			m.timer, cmd = m.timer.Update(msg)
			cmds = append(cmds, cmd)
		}
	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	case timer.TickMsg:
		m.timer, cmd = m.timer.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m crackstationModel) View() string {

	doc := strings.Builder{}
	status := m.c.Status()

	w := lipgloss.Width

	statusKey := statusStyle.Render("STATUS")
	encoding := encodingStyle.Render("UTF-8")
	fishCake := fishCakeStyle.Render("🍥 Fish Cake")
	width, _, _ := term.GetSize(int(os.Stdout.Fd()))
	statusVal := statusText.Copy().
		Width(width - w(statusKey) - w(encoding) - w(fishCake)).
		Render("Ravishing")
	bar := lipgloss.JoinHorizontal(lipgloss.Top,
		statusKey,
		statusVal,
		encoding,
		fishCake,
	)
	doc.WriteString(statusBarStyle.Width(width).Render(bar))

	doc.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Top,
		crackstationStyle.Render(fmt.Sprintf("Name: %s\nID: %s\n", status.Name, status.HostUUID)),
		modelStyle.Render(fmt.Sprintf("%v", m.timer.View())),
	))

	//s += lipgloss.JoinHorizontal(lipgloss.Top, modelStyle.Render(fmt.Sprintf("%4s", m.timer.View())), focusedModelStyle.Render(m.spinner.View()))

	doc.WriteString(helpStyle.Render("\n • q: exit\n"))
	return doc.String()
}

func (m *crackstationModel) Next() {
	if m.index == len(spinners)-1 {
		m.index = 0
	} else {
		m.index++
	}
}

func (m *crackstationModel) resetSpinner() {
	m.spinner = spinner.New()
	m.spinner.Style = spinnerStyle
	m.spinner.Spinner = spinners[m.index]
}
