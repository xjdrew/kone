package application

import (
	"os/exec"

	commandutil "github.com/xjdrew/kone/pkg/internal/command"
)

func prepareBackground(command *exec.Cmd) {
	commandutil.Background(command)
}
