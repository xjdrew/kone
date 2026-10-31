//go:build linux

package tun

import (
	"net/netip"
	"strings"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

func (r *autoRedirect) setupNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return E.Cause(err, "create nftables connection")
	}
	defer nft.CloseLasting()

	table := nft.AddTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftables.TableFamilyINet,
	})

	err = r.nftablesCreateAddressSets(nft, table, false)
	if err != nil {
		return E.Cause(err, "create address sets")
	}

	err = r.interfaceFinder.Update()
	if err != nil {
		return E.Cause(err, "update interfaces")
	}
	r.localAddresses = common.FlatMap(r.interfaceFinder.Interfaces(), func(it control.Interface) []netip.Prefix {
		return common.Filter(it.Addresses, func(prefix netip.Prefix) bool {
			return it.Name == "lo" || prefix.Addr().IsGlobalUnicast()
		})
	})
	err = r.nftablesCreateLocalAddressSets(nft, table, r.localAddresses, nil)
	if err != nil {
		return E.Cause(err, "create local address sets")
	}

	err = r.nftablesCreateLoopbackAddressSets(nft, table)
	if err != nil {
		return E.Cause(err, "create loopback address sets")
	}

	if r.nfqueueEnabled {
		err = r.nftablesCreatePreMatchChains(nft, table)
		if err != nil {
			return E.Cause(err, "create pre-match chains")
		}
	}

	if !r.shouldSkipOutputChain() {
		outputNATPriority := nftables.ChainPriorityMangle
		if r.nfqueueEnabled {
			outputNATPriority = nftables.ChainPriorityRef(*nftables.ChainPriorityMangle + 2)
		}
		chainOutput := nft.AddChain(&nftables.Chain{
			Name:     "output",
			Table:    table,
			Hooknum:  nftables.ChainHookOutput,
			Priority: outputNATPriority,
			Type:     nftables.ChainTypeNAT,
		})
		if r.tunOptions.AutoRedirectMarkMode {
			err = r.nftablesCreateExcludeRules(nft, table, chainOutput)
			if err != nil {
				return E.Cause(err, "create output exclude rules")
			}
			r.nftablesCreateUnreachable(nft, table, chainOutput)
			err = r.nftablesCreateRedirect(nft, table, chainOutput)
			if err != nil {
				return E.Cause(err, "create output redirect")
			}
			if len(r.tunOptions.Inet4LoopbackAddress) > 0 || len(r.tunOptions.Inet6LoopbackAddress) > 0 {
				chainOutputRoute := nft.AddChain(&nftables.Chain{
					Name:     "output_route",
					Table:    table,
					Hooknum:  nftables.ChainHookOutput,
					Priority: outputNATPriority,
					Type:     nftables.ChainTypeRoute,
				})
				err = r.nftablesCreateLoopbackReroute(nft, table, chainOutputRoute)
				if err != nil {
					return E.Cause(err, "create output loopback reroute")
				}
			}
			chainOutputUDP := nft.AddChain(&nftables.Chain{
				Name:     "output_udp_icmp",
				Table:    table,
				Hooknum:  nftables.ChainHookOutput,
				Priority: outputNATPriority,
				Type:     nftables.ChainTypeRoute,
			})
			err = r.nftablesCreateExcludeRules(nft, table, chainOutputUDP)
			if err != nil {
				return E.Cause(err, "create output udp exclude rules")
			}
			r.nftablesCreateUnreachable(nft, table, chainOutputUDP)
			r.nftablesCreateMark(nft, table, chainOutputUDP)
		} else {
			err = r.nftablesCreateRedirect(nft, table, chainOutput, &expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: 1,
			}, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     nftablesIfname(r.tunOptions.Name),
			})
			if err != nil {
				return E.Cause(err, "create output redirect")
			}
		}
	}

	if r.redirectServer != nil {
		chainInput := nft.AddChain(&nftables.Chain{
			Name:     "input",
			Table:    table,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
		})
		r.nftablesCreateRedirectPortReject(nft, table, chainInput)
	}

	preroutingNATPriority := nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 1)
	preroutingRoutePriority := nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 2)
	if r.nfqueueEnabled {
		preroutingNATPriority = nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 2)
		preroutingRoutePriority = nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 3)
	}
	chainPreRouting := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: preroutingNATPriority,
		Type:     nftables.ChainTypeNAT,
	})
	err = r.nftablesCreateExcludeRules(nft, table, chainPreRouting)
	if err != nil {
		return E.Cause(err, "create prerouting exclude rules")
	}
	r.nftablesCreateUnreachable(nft, table, chainPreRouting)
	err = r.nftablesCreateRedirect(nft, table, chainPreRouting)
	if err != nil {
		return E.Cause(err, "create prerouting redirect")
	}
	if r.tunOptions.AutoRedirectMarkMode {
		r.nftablesCreateMark(nft, table, chainPreRouting)
		if len(r.tunOptions.Inet4LoopbackAddress) > 0 || len(r.tunOptions.Inet6LoopbackAddress) > 0 {
			chainPreRoutingFilter := nft.AddChain(&nftables.Chain{
				Name:     "prerouting_filter",
				Table:    table,
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: preroutingNATPriority,
				Type:     nftables.ChainTypeFilter,
			})
			err = r.nftablesCreateLoopbackReroute(nft, table, chainPreRoutingFilter)
			if err != nil {
				return E.Cause(err, "create prerouting loopback reroute")
			}
		}
		chainPreRoutingUDP := nft.AddChain(&nftables.Chain{
			Name:     "prerouting_udp_icmp",
			Table:    table,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: preroutingRoutePriority,
			Type:     nftables.ChainTypeFilter,
		})
		ipProto := &nftables.Set{
			Table:     table,
			Anonymous: true,
			Constant:  true,
			KeyType:   nftables.TypeInetProto,
		}
		err = nft.AddSet(ipProto, []nftables.SetElement{
			{Key: []byte{unix.IPPROTO_UDP}},
			{Key: []byte{unix.IPPROTO_ICMP}},
			{Key: []byte{unix.IPPROTO_ICMPV6}},
		})
		if err != nil {
			return E.Cause(err, "add ip protocol set")
		}
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRoutingUDP,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: 1,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetID:          ipProto.ID,
					SetName:        ipProto.Name,
					Invert:         true,
				},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRoutingUDP,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyIIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.Name),
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRoutingUDP,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyIIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.Name),
				},
				&expr.Ct{
					Key:      expr.CtKeyMARK,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(r.tunOptions.AutoRedirectInputMark),
				},
				&expr.Meta{
					Key:            expr.MetaKeyMARK,
					Register:       1,
					SourceRegister: true,
				},
				&expr.Counter{},
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRoutingUDP,
			Exprs: []expr.Any{
				&expr.Ct{
					Key:      expr.CtKeyMARK,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(r.tunOptions.AutoRedirectInputMark),
				},
				&expr.Immediate{
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(r.tunOptions.AutoRedirectOutputMark),
				},
				&expr.Meta{
					Key:            expr.MetaKeyMARK,
					Register:       1,
					SourceRegister: true,
				},
				&expr.Meta{
					Key:      expr.MetaKeyMARK,
					Register: 1,
				},
				&expr.Ct{
					Key:            expr.CtKeyMARK,
					Register:       1,
					SourceRegister: true,
				},
				&expr.Counter{},
			},
		})
	}

	err = r.configureOpenWRTFirewall4(nft, false)
	if err != nil {
		return E.Cause(err, "configure openwrt firewall4")
	}
	err = nft.Flush()
	if err != nil {
		return E.Cause(err, "flush nftables")
	}
	if r.tunOptions.NetNs == "" {
		r.startDockerFirewallMonitor()
		err = r.configureDockerFirewall(false)
		if err != nil && r.logger != nil {
			r.logger.Warn("configure docker firewall: ", err)
		}
	}

	r.networkListener = r.networkMonitor.RegisterCallback(func() {
		updateErr := runInNetworkNamespace(r.tunOptions.NetNs, r.updateNetworkAddresses)
		if updateErr != nil {
			r.logger.Error(updateErr)
		}
	})
	return nil
}

func (r *autoRedirect) updateNetworkAddresses() error {
	err := r.nftablesUpdateLocalAddressSet()
	if err != nil {
		err = E.Cause(err, "update local address set")
	}
	if r.tunOptions.AutoRedirectMarkMode {
		routeErr := r.updateRedirectRoutes()
		if routeErr != nil {
			routeErr = E.Cause(routeErr, "update redirect routes")
		}
		err = E.Errors(err, routeErr)
	}
	return err
}

func (r *autoRedirect) nftablesUpdateLocalAddressSet() error {
	err := r.interfaceFinder.Update()
	if err != nil {
		return E.Cause(err, "update interfaces")
	}
	newLocalAddresses := common.FlatMap(r.interfaceFinder.Interfaces(), func(it control.Interface) []netip.Prefix {
		return common.Filter(it.Addresses, func(prefix netip.Prefix) bool {
			return it.Name == "lo" || prefix.Addr().IsGlobalUnicast()
		})
	})
	if slices.Equal(newLocalAddresses, r.localAddresses) {
		return nil
	}
	if r.logger != nil {
		r.logger.Debug("updating local address set to [", strings.Join(common.Map(newLocalAddresses, func(it netip.Prefix) string {
			return it.String()
		}), ", ")+"]")
	}
	nft, err := nftables.New()
	if err != nil {
		return E.Cause(err, "create nftables connection")
	}
	defer nft.CloseLasting()
	table, err := nft.ListTableOfFamily(r.tableName, nftables.TableFamilyINet)
	if err != nil {
		return E.Cause(err, "list nftables table")
	}
	err = r.nftablesCreateLocalAddressSets(nft, table, newLocalAddresses, r.localAddresses)
	if err != nil {
		return E.Cause(err, "create local address sets")
	}
	r.localAddresses = newLocalAddresses
	return nft.Flush()
}

func (r *autoRedirect) nftablesUpdateRouteAddressSet() error {
	nft, err := nftables.New()
	if err != nil {
		return E.Cause(err, "create nftables connection")
	}
	defer nft.CloseLasting()
	table, err := nft.ListTableOfFamily(r.tableName, nftables.TableFamilyINet)
	if err != nil {
		return E.Cause(err, "list nftables table")
	}
	err = r.nftablesCreateAddressSets(nft, table, true)
	if err != nil {
		return E.Cause(err, "create address sets")
	}
	return nft.Flush()
}

func (r *autoRedirect) cleanupNFTables() {
	if r.networkListener != nil {
		r.networkMonitor.UnregisterCallback(r.networkListener)
		r.networkListener = nil
	}
	r.stopDockerFirewallMonitor()
	nft, err := nftables.New()
	if err != nil {
		return
	}
	nft.DelTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftables.TableFamilyINet,
	})
	_ = r.configureOpenWRTFirewall4(nft, true)
	_ = nft.Flush()
	_ = nft.CloseLasting()
	if r.tunOptions.NetNs == "" {
		err = r.configureDockerFirewall(true)
		if err != nil && r.logger != nil {
			r.logger.Warn("cleanup docker firewall: ", err)
		}
	}
}

func (r *autoRedirect) nftablesCreatePreMatchChains(nft *nftables.Conn, table *nftables.Table) error {
	// Every nat chain of a hook is evaluated from the single nat hook netfilter registers at
	// NF_IP_PRI_NAT_DST, whatever priority the chain itself declares, so a chain that must see the
	// original destination has to sit below that priority rather than below the redirect chain.
	chainPreroutingPreMatch := nft.AddChain(&nftables.Chain{
		Name:     "prerouting_prematch",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 1),
		Type:     nftables.ChainTypeFilter,
	})
	err := r.nftablesAddPreMatchRules(nft, table, chainPreroutingPreMatch, true)
	if err != nil {
		return err
	}

	if r.tunOptions.AutoRedirectMarkMode && !r.shouldSkipOutputChain() {
		chainOutputPreMatch := nft.AddChain(&nftables.Chain{
			Name:     "output_prematch",
			Table:    table,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityMangle + 1),
			Type:     nftables.ChainTypeRoute,
		})
		err = r.nftablesAddPreMatchRules(nft, table, chainOutputPreMatch, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *autoRedirect) nftablesAddPreMatchRules(nft *nftables.Conn, table *nftables.Table, chain *nftables.Chain, isPrerouting bool) error {
	if isPrerouting {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftablesIfname(r.tunOptions.Name)},
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
		})
	}
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	for _, mark := range []uint32{r.effectiveOutputMark(), r.tunOptions.AutoRedirectInputMark} {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
				&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
		})
	}

	if r.enableIPv4 != r.enableIPv6 {
		disabledFamily := nftables.TableFamilyIPv6
		if r.enableIPv6 {
			disabledFamily = nftables.TableFamilyIPv4
		}
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{uint8(disabledFamily)}},
				&expr.Verdict{Kind: expr.VerdictReturn},
			},
		})
	}

	preMatchProtocols := &nftables.Set{
		Table:     table,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetProto,
	}
	preMatchProtocolElements := []nftables.SetElement{{Key: []byte{unix.IPPROTO_TCP}}}
	if r.tunOptions.AutoRedirectMarkMode {
		preMatchProtocolElements = append(preMatchProtocolElements,
			nftables.SetElement{Key: []byte{unix.IPPROTO_UDP}},
			nftables.SetElement{Key: []byte{unix.IPPROTO_ICMP}},
			nftables.SetElement{Key: []byte{unix.IPPROTO_ICMPV6}},
		)
	}
	err := nft.AddSet(preMatchProtocols, preMatchProtocolElements)
	if err != nil {
		return E.Cause(err, "add pre-match protocol set")
	}
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Lookup{
				SourceRegister: 1,
				SetID:          preMatchProtocols.ID,
				SetName:        preMatchProtocols.Name,
				Invert:         true,
			},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        13,
				Len:           1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            1,
				Mask:           []byte{0x12},
				Xor:            []byte{0x00},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x02}},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(r.effectiveResetMark())},
			&expr.Counter{},
			&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
		},
	})

	err = r.nftablesCreateExcludeRules(nft, table, chain)
	if err != nil {
		return err
	}

	queueExpression := func() *expr.Queue {
		return &expr.Queue{
			Num:  r.effectiveNFQueue(),
			Flag: expr.QueueFlagBypass,
		}
	}

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Counter{},
			queueExpression(),
		},
	})

	if r.tunOptions.AutoRedirectMarkMode {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Counter{},
				queueExpression(),
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(header.ICMPv4Echo), 0}},
				&expr.Counter{},
				queueExpression(),
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(header.ICMPv6EchoRequest), 0}},
				&expr.Counter{},
				queueExpression(),
			},
		})
	}
	return nil
}
