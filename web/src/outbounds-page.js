export function outboundRuleReferences(rules = [], name) {
  return rules.map((rule, index) => ({ ...rule, order: index + 1 }))
    .filter(rule => rule.outbound === name);
}

export function createOutboundsPage(ui) {
  const { model, h, button, empty, readonlyNote, outboundAddress, currentHealth } = ui;
  const references = (rules, name) => {
    const count = outboundRuleReferences(rules, name).length;
    return h("span", { class: "outbound-reference-count", "data-outbound-references": name,
      title: "已保存规则的引用数量，包含显式 FINAL；不计内置默认兜底。" }, `${count} 条规则`);
  };
  function builtin(name, label, description, rules) {
    const refs = outboundRuleReferences(rules, name);
    return h("details", { class: "builtin-outbound", "data-builtin-outbound": name,
      open: Boolean(model.outboundBuiltinOpen?.[name]),
      ontoggle: event => { (model.outboundBuiltinOpen ||= {})[name] = event.target.open; } },
      h("summary", {}, h("span", { class: "builtin-outbound-name" }, label, h("code", {}, name)),
        references(rules, name), h("span", { class: "builtin-outbound-view", "aria-hidden": true }, "查看 ›")),
      h("div", { class: "builtin-outbound-detail" },
        h("p", {}, description),
        name === "direct" && !rules.some(rule => rule.type === "FINAL") && h("p", {}, "没有显式 FINAL 时，内置默认兜底仍使用直连。"),
        refs.length ? h("ul", { "aria-label": "引用规则" }, refs.map(rule => h("li", {},
          `${rule.order}. ${rule.type}${rule.pattern ? " " + rule.pattern : ""}${rule["expires-at"] && Date.parse(rule["expires-at"]) <= Date.now() ? " · 已到期" : ""}`)))
          : h("p", { class: "muted" }, "没有已保存规则引用。"),
      ),
    );
  }
  return function renderOutbounds() {
    const values = model.config?.config?.outbounds || [];
    const rules = model.config?.config?.rules || [];
    return [readonlyNote(), ui.versions(), h("div", { class: "outbounds-page" },
      h("section", { class: "builtin-outbounds", "data-builtin-outbounds": "", "aria-label": "内置出站" },
        h("h2", { class: "outbound-section-title" }, "内置出站"),
        h("div", { class: "builtin-outbound-list" },
          builtin("direct", "直连", "通过主机实际出口连接目标，支持 TCP 与 UDP，无需添加代理配置。", rules),
          builtin("reject", "拒绝", "拒绝命中的连接，不拨号，也不回退到其他出站。", rules),
        ),
      ),
      h("section", { class: "proxy-outbounds", "aria-label": "代理出站" },
        h("div", { class: "outbound-section-heading" }, h("h2", { class: "outbound-section-title" }, "代理出站"),
          button("＋ 添加代理", () => ui.addOutbound(), "primary compact")),
        values.length ? h("div", { class: "resource-list outbound-list" }, values.map((outbound, index) => {
          const health = (model.outboundHealth || []).find(value => (outbound.id && value.id === outbound.id) || value.name === outbound.name);
          const state = outbound.enabled === false ? "已禁用" : !health || health.stale || health.status === "healthy" && !currentHealth(health) ? "待测试" : ({ healthy: "可用", unhealthy: "测试失败", testing: "测试中", unknown: "待测试" }[health.status] || "待测试");
          const latency = Number.isFinite(health?.connect_latency_ms) ? `${health.connect_latency_ms} ms` : "—";
          const testing = Boolean(model.outboundTests?.[outbound.id || outbound.name]?.running);
          return h("article", { class: "resource-item outbound-item compact-outbound", "data-outbound-row": index },
            h("div", { class: "outbound-row-heading" },
              h("div", { class: "resource-main" },
                h("div", { class: "outbound-name-line" }, h("h3", {}, outbound.name), h("span", { class: "outbound-endpoint" }, outboundAddress(outbound.url))),
                h("div", { class: "outbound-status-line" },
                  h("span", { class: "tag " + (state === "可用" ? "success" : state === "测试失败" ? "error" : "muted") }, state),
                  references(rules, outbound.name),
                  h("span", {}, "连接延迟 ", h("b", { "data-outbound-connect-latency": index }, latency)),
                  health?.stale && h("small", {}, "上次结果已过期"),
                  (health?.checked_at || health?.status === "testing") && health.protocols && h("span", { class: "outbound-protocol-summary" }, ["tcp", "tls", "udp"].map(protocol => h("span", {},
                    `${protocol.toUpperCase()} · ${({ healthy: "成功", failed: "失败", testing: "测试中", unsupported: "不支持", unknown: "未验证" })[health.protocols[protocol]?.status] || "未验证"}`))),
                ),
              ),
              h("div", { class: "button-row resource-actions" },
                button("测试", () => ui.testOutbound(index), "compact", !ui.canManage() || outbound.enabled === false || testing),
                button("编辑", () => ui.edit("outbound", index), "ghost compact"),
                h("details", { class: "resource-more", "data-outbound-more": index }, h("summary", { "aria-label": "更多操作" }, "•••"), button("删除", () => ui.deleteOutbound(index), "danger compact")),
              ),
            ),
            model.outboundTestOpen === (outbound.id || outbound.name) && ui.outboundTestPanel?.(index),
          );
        })) : empty("尚未配置代理", ""),
      ),
    )];
  };
}
