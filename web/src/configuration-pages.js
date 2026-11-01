// Configuration pages show saved state; forms exist only inside an editor.
export function outboundAddress(raw) {
  try {
    const url = new URL(raw);
    return `${url.protocol}//${url.host}`;
  } catch { return "地址尚未配置"; }
}

export function currentHealth(value, now = Date.now()) {
  if (!value || value.status !== "healthy" || value.stale) return false;
  const expiry = Date.parse(value.expires_at || "");
  return Number.isFinite(expiry) && expiry > now;
}

export function createConfigurationPages(ui) {
  const { model, h, card, note, button, badge, detailPairs, empty, readonlyNote, time } = ui;
  const saved = () => model.config?.config || {};
  const locked = () => ["starting", "running", "degraded", "pausing", "stopping"].includes(ui.runtime()) || Boolean(model.state.capture_locked ?? model.config?.capture_locked ?? false);
  const actions = (...buttons) => h("div", { class: "button-row resource-actions" }, buttons);
  const versions = () => h("p", { class: "muted resource-version" }, `已保存 ${model.config?.version ?? "—"} · 运行中 ${model.state.running_version || "尚未启用"}。保存结果与实际接管状态分别显示。`);

  function inbounds() {
    const core = saved().core || {};
    const inbound = model.config?.inbound || {};
    return [readonlyNote(), versions(), card("TUN 接管入口", "入口设置和实际运行状态分别显示；接管不会因查看或编辑而启动。",
      detailPairs([
        ["名称", inbound.name || "TUN"], ["已保存入口", inbound.enabled ? "已启用" : "未启用"],
        ["运行状态", ui.stateLabel()], ["设备", model.state.device || core.tun || "启动时自动分配"],
        ["协议栈", core.stack || "system"], ["IPv4 网段", core.network || "10.192.0.1/16"],
        ["IPv6 网段", core["ipv6-network"] || "关闭"], ["真实出口", core["outbound-interface"] || "系统选择"],
        ["接管范围", core["auto-route"] ? "全部 IPv4（更具体路由优先）" : "Fake-IP 与显式规则"],
      ]), locked() && note("接管运行或切换期间，TUN、出口、协议栈和 DNS 设置已锁定；请先暂停接管再编辑。", "warning"),
      actions(button("编辑入站", () => ui.edit("inbounds"), "primary", !ui.canManage() || locked()), button("运行预检", ui.preflight)),
    )];
  }

  function outbounds() {
    const values = saved().outbounds || [];
    return [readonlyNote(), versions(), card("代理出站", "健康状态来自你明确发起的目标测试；没有测试或结果过期时不会假定可用。",
      actions(button("＋ 添加代理", () => ui.addOutbound(), "primary"), button("刷新状态", ui.refreshHealth, "ghost", !model.online)),
      values.length ? h("div", { class: "resource-list" }, values.map((outbound, index) => {
        const health = (model.outboundHealth || []).find(value => (outbound.id && value.id === outbound.id) || value.name === outbound.name);
        const state = outbound.enabled === false ? "已禁用" : !health || health.stale || health.status === "healthy" && !currentHealth(health) ? "未知 / 待测试" : ({ healthy: "可用", unhealthy: "测试失败", testing: "测试中", unknown: "未知 / 待测试" }[health.status] || "未知");
        return h("article", { class: "resource-item", "data-outbound-row": index },
          h("div", { class: "resource-main" }, h("h3", {}, outbound.name), h("p", {}, outboundAddress(outbound.url)), h("small", {}, `${state}${health?.checked_at ? ` · ${time(health.checked_at)}` : ""}`), health?.message && h("p", { class: "muted" }, health.message)),
          actions(button("详情", () => ui.outboundDetails(index), "ghost", !model.online), button("测试", () => ui.testOutbound(index), "", !ui.canManage() || outbound.enabled === false), button("编辑", () => ui.edit("outbound", index)), button("删除", () => ui.deleteOutbound(index), "danger")),
        );
      })) : empty("尚未配置代理", "可选择仅直连接管；启动前会明确显示此模式并要求确认。"),
    ), card("内置出站", "无需添加或编辑。", detailPairs([["direct", "直连 TCP / UDP；不等于使用代理"], ["reject", "拒绝连接；不执行直连回退"]]))];
  }

  function rules() {
    const values = saved().rules || [];
    return [readonlyNote(), versions(), card("路由规则", "按顺序首个匹配生效，FINAL 在最后；成功热应用只影响新连接。",
      actions(button("＋ 添加精确域名", () => ui.addRule("DOMAIN"), "primary"), button("＋ 添加最终规则", () => ui.addRule("FINAL")), button("模拟规则匹配", ui.simulateRules, "ghost")),
      values.length ? h("div", { class: "resource-list" }, values.map((rule, index) => h("article", { class: "resource-item", "data-rule-row": index },
        h("div", { class: "resource-main" }, h("h3", {}, `${index + 1}. ${rule.type} ${rule.pattern || "默认"}`), h("p", {}, `→ ${rule.outbound || "direct"} · ${(rule.protocol || "TCP / UDP").toUpperCase()}${rule.ports?.length ? ` · ${rule.ports.join(", ")}` : " · 全部端口"}`), rule["expires-at"] && h("small", {}, `到期 ${time(rule["expires-at"])}`)),
        actions(button("编辑", () => ui.edit("rule", index)), button("↑", () => ui.moveRule(index, -1), "ghost", !ui.canManage() || index === 0 || rule.type === "FINAL", { "aria-label": `将规则 ${index + 1} 上移` }), button("↓", () => ui.moveRule(index, 1), "ghost", !ui.canManage() || index === values.length - 1 || rule.type === "FINAL" || values[index + 1]?.type === "FINAL", { "aria-label": `将规则 ${index + 1} 下移` }), button("删除", () => ui.deleteRule(index), "danger")),
      ))) : empty("尚无规则", "未命中时使用内置 direct；可添加精确规则再保存。"),
    )];
  }

  function dns() {
    const config = saved().dns || {};
    return [readonlyNote(), card("DNS 设置", "此处显示已保存设置；下方为实际运行的解析范围和查询记录。",
      detailPairs([["上游", config.servers?.length ? config.servers.join(", ") : "自动发现系统 DNS"], ["系统引导", config.system ? "启用（仍需平台检查）" : "关闭"], ["手工解析规则", `${config.rules?.length || 0} 条`], ["监听端口", config["listen-port"] || 53]]),
      locked() && note("DNS 设置需要先暂停接管再编辑。", "warning"),
      actions(button("编辑 DNS 设置", () => ui.edit("dns"), "primary", !ui.canManage() || locked())),
    ), ...ui.dnsObservations()];
  }

  function settings() {
    const general = saved().general || {};
    return [readonlyNote(), ...ui.settingsObservations(),
      card("日志设置", "采集级别与诊断页的显示筛选不同，修改按保存结果提示生效。", detailPairs([["级别", (general["log-level"] || "info").toUpperCase()], ["格式", general["log-format"] || "text"]]), locked() && note("请先暂停接管，再修改日志采集设置。", "warning"), actions(button("编辑日志设置", () => ui.edit("logs"), "primary", !ui.canManage() || locked()))),
      card("手机与平板访问", "默认回环；局域网入口必须由所有者显式授权。", detailPairs([["访问状态", model.lan.enabled ? "已开启" : "未开启"], ["授权会话", `${(model.sessions.sessions || model.sessions || []).length} 个`]]), actions(button("管理局域网访问", () => ui.edit("lan")))),
      card("GeoIP 数据", "查看来源版本，更新和回退在独立操作面板中确认。", detailPairs([["版本", model.geoip?.saved?.version || "尚未加载"], ["来源", model.geoip?.saved?.source || "内置或已保存数据"]]), model.geoError && note(model.geoError, "error"), actions(button("更新 GeoIP 数据", () => ui.edit("geoip")))),
    ];
  }
  return { inbounds, outbounds, rules, dns, settings };
}
