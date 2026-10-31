package desktop

type TrayActions struct {
	Open        func()
	Pause       func()
	Exit        func()
	Start       func()
	Diagnostics func()
	// State returns the controller's cached state without performing RPC or I/O.
	State func() string
}

func invokeTrayAction(actions TrayActions, id uintptr) {
	switch id {
	case 1:
		if actions.Open != nil {
			go actions.Open()
		}
	case 2:
		if actions.Pause != nil {
			go actions.Pause()
		}
	case 3:
		if actions.Exit != nil {
			go actions.Exit()
		}
	case 4:
		if actions.Start != nil {
			go actions.Start()
		}
	case 5:
		if actions.Diagnostics != nil {
			go actions.Diagnostics()
		}
	}
}

func trayTooltip(actions TrayActions) string {
	if actions.State == nil {
		return "KONE — management available"
	}
	state := actions.State()
	if state == "" {
		state = "state unknown"
	}
	return "KONE — " + state
}
