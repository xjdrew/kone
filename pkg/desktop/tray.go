package desktop

type TrayActions struct {
	Open  func()
	Pause func()
	Exit  func()
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
	}
}
