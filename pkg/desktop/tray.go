package desktop

import (
	"github.com/xjdrew/kone/pkg/locale"
	"sync/atomic"
)

type TrayActions struct {
	Open        func()
	Pause       func()
	Exit        func()
	Start       func()
	Diagnostics func()
	// State returns the controller's cached state without performing RPC or I/O.
	State    func() string
	dispatch *trayActionDispatch
}

type trayActionDispatch struct{ active [6]atomic.Bool }

func prepareTrayActions(actions TrayActions) TrayActions {
	if actions.dispatch == nil {
		actions.dispatch = &trayActionDispatch{}
	}
	return actions
}

func invokeTrayAction(actions TrayActions, id uintptr) {
	// Native entrypoints initialize one dispatcher per menu instance. Refuse
	// an uninitialized source rather than creating a fresh, unbounded slot.
	if actions.dispatch == nil {
		return
	}
	var action func()
	switch id {
	case 1:
		action = actions.Open
	case 2:
		action = actions.Pause
	case 3:
		action = actions.Exit
	case 4:
		action = actions.Start
	case 5:
		action = actions.Diagnostics
	default:
		return
	}
	if action == nil {
		return
	}
	slot := &actions.dispatch.active[id]
	if !slot.CompareAndSwap(false, true) {
		return
	}
	go func() { defer slot.Store(false); action() }()
}

func trayTooltip(actions TrayActions) string {
	if actions.State == nil {
		return locale.Desktop("desktop.available")
	}
	state := actions.State()
	if state == "" {
		state = "unknown"
	}
	return "KONE — " + trayStateLabel(state)
}

func trayStateLabel(state string) string {
	key := "common." + state
	label := locale.Desktop(key)
	if label == key {
		return locale.Desktop("common.unknown")
	}
	return label
}

func trayLabels() map[string]string {
	labels := map[string]string{}
	for _, key := range []string{"open", "start", "pause", "diagnostics", "exit", "stopping"} {
		labels[key] = locale.Desktop("desktop." + key)
	}
	for _, key := range []string{"running", "paused", "starting", "stopping", "failed", "degraded", "unknown"} {
		labels["state_"+key] = trayStateLabel(key)
	}
	return labels
}
