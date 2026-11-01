package kone

import (
	"context"
	"fmt"
	"strings"
)

type windowsRestoreAction struct {
	name, script string
	params       any
}

// Group same-interface restoration in one bounded PowerShell process. Each
// constant script still receives its own JSON parameters and catches its own
// error, so a failed property restore never skips the remaining properties.
type windowsRestoreBatch struct {
	network systemNetwork
	actions []windowsRestoreAction
}

func (b *windowsRestoreBatch) add(name, script string, params any) {
	b.actions = append(b.actions, windowsRestoreAction{name, script, params})
}

func (b *windowsRestoreBatch) restore(ctx context.Context) error {
	if len(b.actions) == 0 {
		return nil
	}
	actions := b.actions
	b.actions = nil
	values, names := make([]any, len(actions)), make([]string, len(actions))
	var script strings.Builder
	script.WriteString(`$koneRestoreInput=$p; $koneRestoreErrors=[System.Collections.Generic.List[string]]::new(); `)
	for i := range actions {
		action := actions[len(actions)-1-i]
		values[i], names[i] = action.params, action.name
		fmt.Fprintf(&script, `try { $p=$koneRestoreInput.Actions[%d]; %s } catch { $koneRestoreErrors.Add([string]$koneRestoreInput.Names[%d]+': '+$_.Exception.Message) }; `, i, action.script, i)
	}
	script.WriteString(`if($koneRestoreErrors.Count -gt 0){throw ($koneRestoreErrors -join '; ')}`)
	_, err := b.network.powershell(ctx, script.String(), map[string]any{"Actions": values, "Names": names})
	return err
}
