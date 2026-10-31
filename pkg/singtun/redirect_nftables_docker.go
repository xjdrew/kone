//go:build linux

package tun

import (
	"bytes"
	"slices"
	"strings"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/nftables/userdata"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	nftablesDockerFilterTable = "filter"
	nftablesDockerUserChain   = "DOCKER-USER"
)

func (r *autoRedirect) startDockerFirewallMonitor() {
	if r.dockerFirewallMonitor != nil {
		return
	}
	doneCh := make(chan struct{})
	r.dockerFirewallDone = doneCh
	monitor := nftables.NewMonitor(
		nftables.WithMonitorAction(nftables.MonitorActionAny),
		nftables.WithMonitorObject(nftables.MonitorObjectRuleset),
		nftables.WithMonitorEventBuffer(16),
	)
	nft, err := nftables.New()
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("create nftables monitor connection: ", err)
		}
		close(doneCh)
		r.dockerFirewallDone = nil
		return
	}
	events, err := nft.AddGenerationalMonitor(monitor)
	_ = nft.CloseLasting()
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("start nftables monitor: ", err)
		}
		close(doneCh)
		r.dockerFirewallDone = nil
		return
	}
	r.dockerFirewallMonitor = monitor
	go r.loopDockerFirewallMonitor(events, doneCh)
}

func (r *autoRedirect) stopDockerFirewallMonitor() {
	if r.dockerFirewallMonitor == nil {
		return
	}
	_ = r.dockerFirewallMonitor.Close()
	<-r.dockerFirewallDone
	r.dockerFirewallMonitor = nil
	r.dockerFirewallDone = nil
}

func (r *autoRedirect) loopDockerFirewallMonitor(events <-chan *nftables.MonitorEvents, doneCh chan<- struct{}) {
	defer close(doneCh)
	for monitorEvents := range events {
		if monitorEvents != nil && monitorEvents.GeneratedBy != nil && monitorEvents.GeneratedBy.Error != nil {
			if r.logger != nil {
				r.logger.Warn("nftables monitor closed: ", monitorEvents.GeneratedBy.Error)
			}
			return
		}
		if !nftablesDockerFirewallEventsRelevant(monitorEvents) {
			continue
		}
		err := r.configureDockerFirewall(false)
		if err != nil && r.logger != nil {
			r.logger.Warn("update docker firewall: ", err)
		}
	}
}

func (r *autoRedirect) configureDockerFirewall(cleanup bool) error {
	nft, err := nftables.New()
	if err != nil {
		return E.Cause(err, "create nftables connection")
	}
	defer nft.CloseLasting()

	err = r.configureDockerFirewallWithConn(nft, cleanup)
	if err != nil {
		return err
	}
	return nft.Flush()
}

func (r *autoRedirect) configureDockerFirewallWithConn(nft *nftables.Conn, cleanup bool) error {
	var err error
	if r.enableIPv4 {
		err = E.Errors(err, r.configureDockerFirewallForFamily(nft, nftables.TableFamilyIPv4, cleanup))
	}
	if r.enableIPv6 {
		err = E.Errors(err, r.configureDockerFirewallForFamily(nft, nftables.TableFamilyIPv6, cleanup))
	}
	return err
}

func (r *autoRedirect) configureDockerFirewallForFamily(nft *nftables.Conn, family nftables.TableFamily, cleanup bool) error {
	table, chain, loaded, err := nftablesLoadDockerUserChain(nft, family)
	if err != nil || !loaded {
		return err
	}
	err = r.configureDockerFirewallRules(nft, table, chain, cleanup)
	return err
}

func (r *autoRedirect) configureDockerFirewallRules(nft *nftables.Conn, table *nftables.Table, chain *nftables.Chain, cleanup bool) error {
	rules, err := nft.GetRules(table, chain)
	if err != nil {
		return E.Cause(err, "list docker user rules")
	}
	if cleanup {
		return r.cleanupDockerFirewallRules(nft, rules)
	}
	return r.reconcileDockerFirewallRules(nft, table, chain, rules)
}

func nftablesLoadDockerUserChain(nft *nftables.Conn, family nftables.TableFamily) (*nftables.Table, *nftables.Chain, bool, error) {
	table, err := nft.ListTableOfFamily(nftablesDockerFilterTable, family)
	if err != nil {
		return nil, nil, false, nil
	}
	chain, err := nft.ListChain(table, nftablesDockerUserChain)
	if err != nil {
		return nil, nil, false, nil
	}
	return table, chain, true, nil
}

func nftablesDockerFirewallEventsRelevant(events *nftables.MonitorEvents) bool {
	if events == nil {
		return false
	}
	return slices.ContainsFunc(events.Changes, nftablesDockerFirewallEventRelevant)
}

func nftablesDockerFirewallEventRelevant(event *nftables.MonitorEvent) bool {
	if event == nil || event.Error != nil {
		return false
	}
	switch data := event.Data.(type) {
	case *nftables.Table:
		return nftablesIsDockerFirewallTable(data)
	case *nftables.Chain:
		return data.Name == nftablesDockerUserChain && nftablesIsDockerFirewallTable(data.Table)
	case *nftables.Rule:
		return data.Chain != nil && data.Chain.Name == nftablesDockerUserChain && nftablesIsDockerFirewallTable(data.Table)
	default:
		return false
	}
}

func nftablesIsDockerFirewallTable(table *nftables.Table) bool {
	return table != nil &&
		table.Name == nftablesDockerFilterTable &&
		(table.Family == nftables.TableFamilyIPv4 || table.Family == nftables.TableFamilyIPv6)
}

func (r *autoRedirect) cleanupDockerFirewallRules(nft *nftables.Conn, rules []*nftables.Rule) error {
	var deleteErr error
	for _, rule := range rules {
		if r.nftablesIsDockerCompatibilityRule(rule) {
			deleteErr = E.Errors(deleteErr, nft.DelRule(rule))
		}
	}
	return deleteErr
}

func (r *autoRedirect) reconcileDockerFirewallRules(nft *nftables.Conn, table *nftables.Table, chain *nftables.Chain, rules []*nftables.Rule) error {
	outputComment := r.nftablesDockerCompatibilityComment("output to tun")
	inputComment := r.nftablesDockerCompatibilityComment("input from tun")
	var hasOutputRule bool
	var hasInputRule bool
	var deleteErr error
	for _, rule := range rules {
		if nftablesDockerCompatibilityRuleMatches(rule, r.tunOptions.Name, expr.MetaKeyOIFNAME, outputComment) && !hasOutputRule {
			hasOutputRule = true
		} else if nftablesDockerCompatibilityRuleMatches(rule, r.tunOptions.Name, expr.MetaKeyIIFNAME, inputComment) && !hasInputRule {
			hasInputRule = true
		} else if r.nftablesIsDockerCompatibilityRule(rule) {
			deleteErr = E.Errors(deleteErr, nft.DelRule(rule))
		}
	}
	if deleteErr != nil {
		return deleteErr
	}
	if !hasOutputRule {
		nft.InsertRule(nftablesDockerCompatibilityRule(table, chain, r.tunOptions.Name, expr.MetaKeyOIFNAME, outputComment))
	}
	if !hasInputRule {
		nft.InsertRule(nftablesDockerCompatibilityRule(table, chain, r.tunOptions.Name, expr.MetaKeyIIFNAME, inputComment))
	}
	return nil
}

func nftablesDockerCompatibilityRule(table *nftables.Table, chain *nftables.Chain, ifName string, ifNameKey expr.MetaKey, comment string) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      ifNameKey,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     nftablesIfname(ifName),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
		UserData: userdata.AppendString(nil, userdata.TypeComment, comment),
	}
}

func nftablesDockerCompatibilityRuleMatches(rule *nftables.Rule, ifName string, ifNameKey expr.MetaKey, comment string) bool {
	ruleComment, loaded := userdata.GetString(rule.UserData, userdata.TypeComment)
	if !loaded || ruleComment != comment || len(rule.Exprs) != 4 {
		return false
	}
	meta, loaded := rule.Exprs[0].(*expr.Meta)
	if !loaded || meta.Key != ifNameKey || meta.Register != 1 {
		return false
	}
	cmp, loaded := rule.Exprs[1].(*expr.Cmp)
	if !loaded || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || !bytes.Equal(cmp.Data, nftablesIfname(ifName)) {
		return false
	}
	_, loaded = rule.Exprs[2].(*expr.Counter)
	if !loaded {
		return false
	}
	verdict, loaded := rule.Exprs[3].(*expr.Verdict)
	return loaded && verdict.Kind == expr.VerdictAccept
}

func (r *autoRedirect) nftablesIsDockerCompatibilityRule(rule *nftables.Rule) bool {
	comment, loaded := userdata.GetString(rule.UserData, userdata.TypeComment)
	return loaded && strings.HasPrefix(comment, r.nftablesDockerCompatibilityCommentPrefix())
}

func (r *autoRedirect) nftablesDockerCompatibilityComment(direction string) string {
	return r.nftablesDockerCompatibilityCommentPrefix() + direction
}

func (r *autoRedirect) nftablesDockerCompatibilityCommentPrefix() string {
	return "!" + r.tableName + ": Docker compatibility "
}
