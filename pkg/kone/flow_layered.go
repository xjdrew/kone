package kone

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"strconv"
	"time"
)

func (h *flowHandler) resolveLayeredDestination(ctx context.Context, s *runtimeSnapshot, destination M.Socksaddr, udp bool, observation *ObservedFlow) (flowTarget, error) {
	target := flowTarget{}
	defer func() {
		if observation != nil {
			target.decision.ConfigVersion = s.configurationVersion()
			observation.Decision(target.decision, target.outbound, target.realDestination, false)
		}
	}()
	destination = destination.Unwrap()
	if !destination.Addr.Is4() && (!destination.Addr.Is6() || h.one.dnsTable6 == nil) {
		return target, errors.New("IPv6 interception is not configured")
	}
	protocol := "tcp"
	if udp {
		protocol = "udp"
	}
	host := destination.Addr.String()
	table := h.one.tableForAddress(destination.Addr)
	ip := net.IP(destination.Addr.AsSlice())
	target.decision = s.rule.Decide(ip, protocol, destination.Port)
	if table.IsLocalIP(ip) {
		record := table.GetByIP(ip)
		if record == nil {
			return target, errors.New("unknown virtual address")
		}
		host = record.Hostname
		target.release = table.Pin(host)
		if observation != nil {
			observation.UpdateTarget(host, destination.Addr.String(), net.JoinHostPort(host, strconv.Itoa(int(destination.Port))))
		}
		initial := s.rule.DecideDNS(host, nil, protocol, destination.Port)
		target.decision = initial
		var message *dns.Msg
		if initial.Evidence == "dns_required" {
			if record.resolutionFresh(time.Now()) {
				message = record.resolved.Copy()
			} else {
				if observation != nil {
					observation.Stage("dns")
				}
				kind := uint16(dns.TypeA)
				if destination.Addr.Is6() {
					kind = dns.TypeAAAA
				}
				var err error
				message, err = h.one.dns.ResolveTypeContext(ctx, host, kind)
				if err != nil {
					target.decision.Evidence = "dns_failed"
					return target, err
				}
				table.SetRealIP(host, message)
			}
		}
		target.decision = s.rule.DecideDNS(host, message, protocol, destination.Port)
	}
	target.decision = h.one.health.route(host, destination.Port, protocol, target.decision, s)
	target.decision.ConfigVersion = s.configurationVersion()
	if target.decision.Evidence == "dns_failed" || target.decision.CaptureOnly {
		return target, errors.New("required routing evidence is unavailable")
	}
	target.outbound = target.decision.Outbound
	if err := s.outbounds.CheckEnabled(target.outbound); err != nil {
		return target, err
	}
	if s.rule.OutboundType(target.outbound) == OutboundReject {
		return target, ErrRejected
	}
	if udp {
		var err error
		target.outbound, err = s.outbounds.UDPOutbound(target.outbound)
		if err != nil {
			return target, err
		}
	}
	if len(target.decision.Candidates) > 0 {
		host = target.decision.Candidates[0]
	}
	target.address = net.JoinHostPort(host, strconv.Itoa(int(destination.Port)))
	if net.ParseIP(host) != nil {
		target.realDestination = target.address
	}
	if observation != nil {
		observation.Decision(target.decision, target.outbound, "", false)
	}
	return target, nil
}
