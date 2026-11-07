# KONE 策略边界复现附件

日期：2026-11-07。对应[研究报告](product-direction-2026-11-07.md#3-本次实验确认的四个边界)。

## 范围与结论

基线为 `8d018cd729f7417b7202a652c65a486ae0e2f33f`。四个探针只使用内存映射和回环 DNS，没有启动 TUN、改系统 DNS/路由，也没有建立外部代理连接；配置中的 `socks5://127.0.0.1:9` 仅提供一个可区分的出站名称。

**这些断言特意验证基线的边界或不期望行为。PASS 表示复现成立，不能将它们直接作为期望行为测试加入 CI。** 修复后应按明确的新规格编写回归测试；真实 IP 不携带域名等协议约束则需要验证产品契约，而非假设可以消除。

| 探针 | 观察值 | 证明范围 |
| --- | --- | --- |
| ColdIPExceptionBeforeFinalProxy | 前置 IP 直连例外未生效，选择 office，上游 DNS 查询数 0 | 冷域名缺少真实地址证据时的 DNS 与流决策 |
| CachedRealIPAfterDomainRuleChange | 缓存真实 IP 选择 direct；新 Fake-IP 选择 office | 同次热更新后的两种输入，不涉及真实浏览器缓存实现 |
| FakeIPCollisionAcrossFreshTables | 默认 /16 池的两代映射中，不同域名都取得 10.192.97.89 | 表级重建地址复用条件，不证明实机已发生错误业务投递 |
| MultiAddressRuleAndDialTargetDiffer | 规则匹配 198.51.100.0/24，拨号目标 203.0.113.9:443 | 双地址解析证据下的决定与目标不一致，没有真正向该地址拨号 |

## 复现步骤

需要 Git、Node.js、项目规定的 Go 1.27.3，以及支持 race 的本地 C 工具链。本次环境为 Linux/amd64，使用 Zig 0.14.1 提供 C 编译器；已有正常 C 编译器时无需安装 Zig。探针依赖基线包内的测试辅助函数，因此使用 Go overlay 将临时文件加入 `pkg/kone`，不修改仓库源码。

下面从**包含本文的 KONE 工作树根目录**执行，创建一个固定基线的独立工作树。临时目录保留以便检查；不要在其他版本出现不同结果时仍声称复现了该基线。

```bash
research_doc="$PWD/docs/research/policy-boundaries-2026-11-07.md"
research_tmp="$(mktemp -d)"
git worktree add --detach "$research_tmp/source" 8d018cd729f7417b7202a652c65a486ae0e2f33f
cd "$research_tmp/source"
node --input-type=module - "$research_doc" "$research_tmp" <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const [document, temporary] = process.argv.slice(2);
const match = readFileSync(document, 'utf8').match(/```go\n([\s\S]*?)\n```/);
if (!match) throw new Error('Go probe block not found');
const probe = join(temporary, 'policy_boundaries_test.go');
writeFileSync(probe, match[1] + '\n');
writeFileSync(join(temporary, 'overlay.json'), JSON.stringify({
  Replace: { [join(process.cwd(), 'pkg/kone/research_policy_boundaries_test.go')]: probe },
}));
NODE
CGO_ENABLED=1 go test -overlay "$research_tmp/overlay.json" -race -tags with_gvisor \
  -run '^TestResearch' -count=1 -v ./pkg/kone
```

如需 Zig，可在执行测试前设置 `CC='/实际路径/zig cc'`；不要复制本机临时目录作为自己的工具链路径。上述例子不会更改主工作树的分支。

## 探针源码

```go
package kone

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func researchEngine(t *testing.T, rules []RuleConfig, queries *atomic.Int32) *One {
	cleanProxyEnv(t)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { queries.Add(1); replyA(w, r, "203.0.113.9") })
	upstream := startDNSListeners(t, handler, handler)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{upstream}
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "socks5://127.0.0.1:9"}}
	cfg.Rule = rules
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	return one
}

func TestResearchColdIPExceptionBeforeFinalProxy(t *testing.T) {
	var queries atomic.Int32
	one := researchEngine(t, []RuleConfig{{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}, &queries)
	request := new(dns.Msg)
	request.SetQuestion("cold.example.", dns.TypeA)
	reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	fake := reply.Answer[0].(*dns.A).A
	require.True(t, one.dnsTable.IsLocalIP(fake))
	target, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), M.SocksaddrFromNet(&net.TCPAddr{IP: fake, Port: 443}), false, nil)
	require.NoError(t, err)
	defer target.release()
	require.Equal(t, "office", target.outbound)
	require.Zero(t, queries.Load())
	t.Logf("IP-CIDR direct before FINAL proxy: selected=%s, upstream DNS queries=%d", target.outbound, queries.Load())
}

func TestResearchCachedRealIPAfterDomainRuleChange(t *testing.T) {
	var queries atomic.Int32
	one := researchEngine(t, []RuleConfig{{Schema: "FINAL", Outbound: BuiltinDirect}}, &queries)
	request := new(dns.Msg)
	request.SetQuestion("cached.example.", dns.TypeA)
	reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	real := reply.Answer[0].(*dns.A).A
	require.Equal(t, "203.0.113.9", real.String())
	cfg := one.Snapshot().Config
	cfg.Rule = []RuleConfig{{Schema: "DOMAIN", Pattern: "cached.example", Outbound: "office"}, {Schema: "FINAL", Outbound: BuiltinDirect}}
	require.NoError(t, one.Reload(cfg))
	target, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), M.SocksaddrFromNet(&net.TCPAddr{IP: real, Port: 443}), false, nil)
	require.NoError(t, err)
	require.Equal(t, BuiltinDirect, target.outbound)
	fresh, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	fake := fresh.Answer[0].(*dns.A).A
	next, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), M.SocksaddrFromNet(&net.TCPAddr{IP: fake, Port: 443}), false, nil)
	require.NoError(t, err)
	defer next.release()
	require.Equal(t, "office", next.outbound)
	t.Logf("After domain reload: cached-real-IP=%s, renewed-DNS/Fake-IP=%s", target.outbound, next.outbound)
}

func TestResearchFakeIPCollisionAcrossFreshTables(t *testing.T) {
	address, subnet, err := net.ParseCIDR("10.192.0.1/16")
	require.NoError(t, err)
	seen := map[string]string{}
	for i := 0; i < 1000; i++ {
		domain := fmt.Sprintf("site-%d.example", i)
		table := NewDnsTable(address, subnet)
		record := table.Set(domain, "office")
		require.NotNil(t, record)
		if prior, ok := seen[record.IP.String()]; ok {
			require.NotEqual(t, prior, table.GetByIP(record.IP).Hostname)
			t.Logf("Fresh tables: old cached %s for %s now identifies %s", record.IP, prior, table.GetByIP(record.IP).Hostname)
			return
		}
		seen[record.IP.String()] = domain
	}
	t.Fatal("no collision found")
}

func TestResearchMultiAddressRuleAndDialTargetDiffer(t *testing.T) {
	cleanProxyEnv(t)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		for _, value := range []string{"203.0.113.9", "198.51.100.9"} {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(value)})
		}
		w.WriteMsg(reply)
	})
	upstream := startDNSListeners(t, handler, handler)
	cfg := DefaultConfig()
	cfg.DNS.Servers = []string{upstream}
	cfg.Outbounds = []OutboundConfig{{Name: "office", URL: "socks5://127.0.0.1:9"}}
	cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "203.0.113.0/24", Outbound: "office"}, {Schema: "FINAL", Outbound: BuiltinDirect}}
	one, err := FromConfig(cfg)
	require.NoError(t, err)
	request := new(dns.Msg)
	request.SetQuestion("multi.example.", dns.TypeA)
	reply, err := one.dns.HandleQuery(t.Context(), request, "udp", "client")
	require.NoError(t, err)
	fake := reply.Answer[0].(*dns.A).A
	require.True(t, one.dnsTable.IsLocalIP(fake))
	cfg = one.Snapshot().Config
	cfg.Rule = []RuleConfig{{Schema: "IP-CIDR", Pattern: "198.51.100.0/24", Outbound: BuiltinDirect}, {Schema: "FINAL", Outbound: "office"}}
	require.NoError(t, one.Reload(cfg))
	target, err := one.flows.resolveDestination(t.Context(), one.policy.Load(), M.SocksaddrFromNet(&net.TCPAddr{IP: fake, Port: 443}), false, nil)
	require.NoError(t, err)
	defer target.release()
	require.Equal(t, BuiltinDirect, target.outbound)
	require.Equal(t, "203.0.113.9:443", target.address)
	require.Equal(t, "IP-CIDR 198.51.100.0/24", target.decision.RuleName)
	t.Logf("Rule=%s selected=%s, but dial target=%s", target.decision.RuleName, target.outbound, target.address)
}
```

## 本次运行记录

```text
=== RUN   TestResearchColdIPExceptionBeforeFinalProxy
    research_policy_boundaries_test.go:41: IP-CIDR direct before FINAL proxy: selected=office, upstream DNS queries=0
--- PASS: TestResearchColdIPExceptionBeforeFinalProxy (0.54s)
=== RUN   TestResearchCachedRealIPAfterDomainRuleChange
    research_policy_boundaries_test.go:66: After domain reload: cached-real-IP=direct, renewed-DNS/Fake-IP=office
--- PASS: TestResearchCachedRealIPAfterDomainRuleChange (0.00s)
=== RUN   TestResearchFakeIPCollisionAcrossFreshTables
    research_policy_boundaries_test.go:80: Fresh tables: old cached 10.192.97.89 for site-120.example now identifies site-201.example
--- PASS: TestResearchFakeIPCollisionAcrossFreshTables (0.01s)
=== RUN   TestResearchMultiAddressRuleAndDialTargetDiffer
    research_policy_boundaries_test.go:120: Rule=IP-CIDR 198.51.100.0/24 selected=direct, but dial target=203.0.113.9:443
--- PASS: TestResearchMultiAddressRuleAndDialTargetDiffer (0.01s)
PASS
ok  	github.com/xjdrew/kone/pkg/kone	1.585s
```

另外在相同基线上运行了已有的 reload、DNS TTL、路由引用和进程归属相关测试，启用 `-race -tags with_gvisor`，`pkg/kone` 与 `pkg/process` 均通过；`just quality vet` 通过。没有据此推定 Windows/macOS 原生网络或真实应用缓存已经完成验证。
