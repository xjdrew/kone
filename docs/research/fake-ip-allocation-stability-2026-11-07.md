# Fake-IP 分配稳定性补充实验

日期：2026-11-07。代码基线：`8d018cd729f7417b7202a652c65a486ae0e2f33f`。对应[四问题 proposal 的 3.4 解法](../proposals/policy-layers-and-fake-ip.md#5-34稳定哈希只是候选-稳定归属才是目标)，补充[原始四个探针](policy-boundaries-2026-11-07.md)。

本次使用默认 IPv4 `/16` 地址表，并模拟引擎额外保留地址。不启动 TUN，不修改系统 DNS/路由，不连接外部服务。两个探针启用 `-race -tags with_gvisor` 均通过；**PASS 表示当前边界被复现，不表示已经修复，不应将不期望行为直接固化为 CI 契约。**

| 实验 | 观察 | 结论 |
| --- | --- | --- |
| 相同域名、不同分配顺序 | `site-120.example` 原为 `10.192.97.89`；同序重建不变，碰撞域名先分配后变为 `10.192.0.3` | 哈希候选稳定不等于最终映射稳定，需要保存冲突分配历史 |
| 同一运行期过期回收 | 原地址过期、达到回收条件后，`site-201.example` 获得旧 `10.192.97.89` | 不重启也能出现跨域复用；地址归属不能简单跟随解析缓存 TTL 删除 |

实验验证的是地址表的身份变化条件，不代表已经在真机上复现了错误业务投递，也没有执行断电持久性或跨平台恢复测试。持久化只是建议方案，后续需要单独实施与验收。

## 复现步骤

需要 Git、Node.js、项目规定的 Go 1.27.3 和支持 race 的 C 工具链。本次使用 Linux/amd64、Zig 0.14.1；已有 C 编译器时无需额外安装 Zig。从包含本文的工作树根目录执行：

```bash
research_doc="$PWD/docs/research/fake-ip-allocation-stability-2026-11-07.md"
research_tmp="$(mktemp -d)"
git worktree add --detach "$research_tmp/source" 8d018cd729f7417b7202a652c65a486ae0e2f33f
cd "$research_tmp/source"
node --input-type=module - "$research_doc" "$research_tmp" <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const [document, temporary] = process.argv.slice(2);
const match = readFileSync(document, 'utf8').match(/```go\n([\s\S]*?)\n```/);
if (!match) throw new Error('Go probe block not found');
const probe = join(temporary, 'allocation_stability_test.go');
writeFileSync(probe, match[1] + '\n');
writeFileSync(join(temporary, 'overlay.json'), JSON.stringify({ Replace: {
  [join(process.cwd(), 'pkg/kone/research_allocation_stability_test.go')]: probe,
} }, null, 2));
NODE
CGO_ENABLED=1 go test -overlay "$research_tmp/overlay.json" \
  -race -tags with_gvisor -run '^TestProposal' -count=1 -v ./pkg/kone
```

若需要 Zig，在 `go test` 命令前设置 `CC='/absolute/path/to/zig cc'`。临时工作树和探针保留供检查，测试不会把文件写进基线源码；其他基线输出不同不能直接视作本次实验结果。

## 完整探针

```go
package kone

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func proposalTable(t *testing.T) *DnsTable {
	ip, subnet, err := net.ParseCIDR("10.192.0.1/16")
	require.NoError(t, err)
	table := NewDnsTable(ip, subnet)
	table.ipPool.reserve(table.ipPool.base.Next()) // Match the engine's extra reservation.
	return table
}

func TestProposalStableHashNeedsAllocationHistory(t *testing.T) {
	first := proposalTable(t)
	original := first.Set("site-120.example", "office")
	collision := first.Set("site-201.example", "office")
	require.NotEqual(t, original.IP.String(), collision.IP.String())

	sameOrder := proposalTable(t)
	require.Equal(t, original.IP.String(), sameOrder.Set("site-120.example", "office").IP.String())

	reversed := proposalTable(t)
	newOwner := reversed.Set("site-201.example", "office")
	moved := reversed.Set("site-120.example", "office")
	require.Equal(t, original.IP.String(), newOwner.IP.String())
	require.NotEqual(t, original.IP.String(), moved.IP.String())
	t.Logf("Same domain/hash: original=%s, same-order=%s, reversed-order=%s; original address now belongs to %s", original.IP, sameOrder.Get("site-120.example").IP, moved.IP, reversed.GetByIP(original.IP).Hostname)
}

func TestProposalExpiredMappingCanChangeOwner(t *testing.T) {
	table := proposalTable(t)
	old := table.Set("site-120.example", "office")
	for i := 0; i < 1000; i++ {
		require.NotNil(t, table.Set(fmt.Sprintf("filler-%d.example", i), "office"))
	}
	table.recordsLock.Lock()
	table.records["site-120.example"].Expires = time.Now().Add(-time.Hour)
	table.recordsLock.Unlock()
	table.clearExpiredDomain(time.Now())
	require.Nil(t, table.GetByIP(old.IP))
	replacement := table.Set("site-201.example", "office")
	require.Equal(t, old.IP.String(), replacement.IP.String())
	t.Logf("Without restart: expired %s for %s is reused by %s", old.IP, old.Hostname, table.GetByIP(old.IP).Hostname)
}
```

## 本次结果

```text
=== RUN   TestProposalStableHashNeedsAllocationHistory
    research_allocation_stability_test.go:34: Same domain/hash: original=10.192.97.89, same-order=10.192.97.89, reversed-order=10.192.0.3; original address now belongs to site-201.example
--- PASS: TestProposalStableHashNeedsAllocationHistory (0.00s)
=== RUN   TestProposalExpiredMappingCanChangeOwner
    research_allocation_stability_test.go:50: Without restart: expired 10.192.97.89 for site-120.example is reused by site-201.example
--- PASS: TestProposalExpiredMappingCanChangeOwner (0.01s)
PASS
ok  	github.com/xjdrew/kone/pkg/kone	1.039s
```
