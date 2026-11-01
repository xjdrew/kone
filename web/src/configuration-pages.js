// Configuration pages show saved state; setting forms live in focused subpages.
export const settingsSections = {
  about: ["关于 KONE", "应用版本、能力与许可。"],
  logs: ["日志设置", "调整底层运行日志的采集级别与输出格式。"],
  geoip: ["GeoIP 数据", "查看数据来源，更新或回退地址归属数据。"],
  lan: ["手机与平板访问", "管理局域网入口、设备授权与会话。"],
  account: ["管理密码", "更改本机管理密码，保护你的管理会话。"],
  configuration: ["配置管理", "查看配置版本，导入、应用或撤销变更。"],
  privacy: ["记录与隐私", "了解本机记录，导出配置或清空观察数据。"],
  network: ["网络维护", "查看自动恢复说明，处理需要人工维护的网络状态。"],
};

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

export function needsDirectConfirmation(document, now = Date.now()) {
  return !document.direct_only_confirmed && (document.config?.rules || []).every(rule =>
    rule["expires-at"] && Date.parse(rule["expires-at"]) <= now ||
    !rule.outbound || ["direct", "reject"].includes(rule.outbound));
}

export function createConfigurationPages(ui) {
  const { model, h, card, note, button, badge, detailPairs, empty, readonlyNote, time } = ui;
  const saved = () => model.config?.config || {};
  const locked = () => ["starting", "running", "degraded", "pausing", "stopping"].includes(ui.runtime()) || Boolean(model.state.capture_locked ?? model.config?.capture_locked ?? false);
  const actions = (...buttons) => h("div", { class: "button-row resource-actions" }, buttons);
  const versions = () => model.state.running_version && model.state.running_version !== model.config?.version ? note("有已保存的更改等待应用。", "warning") : null;

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
      actions(button("编辑入站", () => ui.edit("inbounds"), "primary", !ui.canManage() || locked())),
    )];
  }

  function outbounds() {
    const values = saved().outbounds || [];
    return [readonlyNote(), versions(), card("代理出站", "保存后可按需测试；测试会连接代理端点与指定目标，不发送应用请求。",
      actions(button("＋ 添加代理", () => ui.addOutbound(), "primary")),
      values.length ? h("div", { class: "resource-list outbound-list" }, values.map((outbound, index) => {
        const health = (model.outboundHealth || []).find(value => (outbound.id && value.id === outbound.id) || value.name === outbound.name);
        const state = outbound.enabled === false ? "已禁用" : !health || health.stale || health.status === "healthy" && !currentHealth(health) ? "待测试" : ({ healthy: "可用", unhealthy: "测试失败", testing: "测试中", unknown: "待测试" }[health.status] || "待测试");
        const latency = Number.isFinite(health?.connect_latency_ms) ? health.connect_latency_ms + " ms" : "—";
        const testing = Boolean(model.outboundTests?.[outbound.id || outbound.name]?.running);
        return h("article", { class: "resource-item outbound-item", "data-outbound-row": index },
          h("div", { class: "outbound-row-heading" },
            h("div", { class: "resource-main" },
              h("h3", {}, outbound.name),
              h("p", {}, outboundAddress(outbound.url)),
              h("div", { class: "outbound-status-line" }, h("span", { class: "tag " + (state === "可用" ? "success" : state === "测试失败" ? "error" : "muted") }, state),
                h("span", {}, "连接延迟 ", h("b", { "data-outbound-connect-latency": index }, latency)),
                health?.stale && h("small", {}, "上次结果已过期"),
              ),
            ),
            actions(button("测试", () => ui.testOutbound(index), "", !ui.canManage() || outbound.enabled === false || testing),
              button("编辑", () => ui.edit("outbound", index), "ghost"),
              h("details", { class: "resource-more", "data-outbound-more": index }, h("summary", { "aria-label": "更多操作" }, "•••"), button("删除", () => ui.deleteOutbound(index), "danger compact"))),
          ),
          health?.protocols && h("div", { class: "outbound-protocol-summary" }, ["tcp", "tls", "udp"].map(protocol => h("span", { class: "tag muted" }, protocol.toUpperCase() + " · " + ({ healthy: "成功", failed: "失败", testing: "测试中", unsupported: "不支持", unknown: "未验证" }[health.protocols[protocol]?.status] || "未验证")))),
          model.outboundTestOpen === (outbound.id || outbound.name) && ui.outboundTestPanel?.(index),
        );
      })) : empty("尚未配置代理", "添加已有代理信息，然后按需测试连接。"),
    ), h("details", { class: "disclosure builtin-summary" }, h("summary", {}, "内置出站"), detailPairs([["direct", "直连 TCP / UDP"], ["reject", "拒绝连接"]]))];
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
    if (model.settingsSection) return [ui.settingsDetail(model.settingsSection)];
    const general = saved().general || {};
    const resetLocked = locked() || ui.runtime() === "preflight";
    const paths = { logs: "M5 6h14M5 12h14M5 18h9", geoip: "M3 12h18M12 3c5 5 5 13 0 18M12 3c-5 5-5 13 0 18", lan: "M4 7h16M4 17h16M7 4 4 7l3 3m10 4 3 3-3 3", account: "M7 10V7a5 5 0 0 1 10 0v3M5 10h14v11H5zM12 14v3", configuration: "M4 7h16M4 17h16M9 4v6m6 4v6", privacy: "m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM9 12l2 2 4-4", network: "M20 8a8 8 0 1 0 0 8M20 3v5h-5" };
    const icon = id => h("span", { class: `settings-row-icon settings-icon-${id}`, "aria-hidden": true }, id === "about" ? h("img", { src: "/icon.svg", alt: "", width: 27, height: 27 }) : h("svg", { viewBox: "0 0 24 24", width: 19, height: 19, fill: "none", stroke: "currentColor", "stroke-width": 1.7, "stroke-linecap": "round", "stroke-linejoin": "round" }, id === "geoip" && h("circle", { cx: 12, cy: 12, r: 9 }), h("path", { d: paths[id] })));
    const link = (id, summary) => h("a", { class: "settings-row", href: `#settings/${id}`, "data-settings-link": id },
      icon(id), h("span", { class: "settings-row-title" }, settingsSections[id][0]),
      h("span", { class: "settings-row-value" }, summary), h("span", { class: "settings-chevron", "aria-hidden": true }, "›"));
    const group = (id, title, ...rows) => h("section", { class: "settings-group", "data-settings-group": id, "aria-label": title || (id === "about" ? "关于 KONE" : "账号操作") }, title && h("h2", { class: "settings-group-title" }, title), h("div", { class: "settings-list" }, rows));
    const danger = (id, text, fn, disabled) => button(text, fn, "settings-danger-row", disabled, { "data-settings-action": id });
    return [h("div", { class: "settings-root", "data-settings-root": "" }, readonlyNote(),
      group("about", "", link("about", model.state.version || model.state.build?.version || "开发版本")),
      group("application", "应用设置", link("logs", (general["log-level"] || "info").toUpperCase()), link("geoip", model.geoip?.saved?.version || "查看数据")),
      group("security", "访问与安全", link("lan", model.lan.enabled ? "已开启" : "未开启"), link("account", "修改密码")),
      group("maintenance", "数据维护", link("configuration", `版本 ${model.config?.version ?? "—"}`), link("privacy", "本机处理"), link("network", "自动恢复")),
      group("actions", "", danger("reset", "重置所有配置", ui.resetConfiguration, !ui.canManage() || resetLocked || Boolean(model.state.remote_session)), danger("logout", "退出登录", ui.logout, !model.online || model.authBusy || model.busy)),
      h("p", { class: "settings-footnote" }, resetLocked ? "接管运行期间无法重置配置，请先暂停接管。" : model.state.remote_session ? "重置所有配置需要在 KONE 主机本机操作。" : "重置配置会保留管理密码与本机登录。"),
    )];
  }
  return { inbounds, outbounds, rules, dns, settings };
}
