import { logFieldPreview } from "./logs.js";

// This view owns its DOM for the lifetime of the authenticated session. Polls
// update data cells without replacing filters, scroll containers or disclosures.
export function createDiagnosticsPage(ui) {
  const { model, h, button, time } = ui;
  const rows = new Map();
  const sources = { management: "管理", desktop: "桌面", helper: "提权辅助进程" };
  const toolArea = h("div", { class: "diagnostics-tools", "data-diagnostics-tools": "" },
    button("新建诊断", ui.openDiagnostic, "primary compact", !ui.canManage(), { "data-new-diagnostic": "" }),
  );
  const tools = [
    ["candidates", "待诊断目标"], ["tasks", "诊断与控制任务"],
  ].map(([key, title]) => {
    const body = h("div", { class: "diagnostic-tool-body" });
    const summary = h("summary", {}, title);
    const details = h("details", { class: "diagnostic-tool", [`data-diagnostic-${key}`]: "" }, summary, body);
    toolArea.append(details);
    return { key, title, details, summary, body, signature: "" };
  });
  const level = h("select", { id: "log-level", value: model.logLevel, onchange: event => ui.filter("logLevel", event.target.value) },
    ["debug", "info", "warn", "error"].map(value => h("option", { value }, value.toUpperCase())));
  const source = h("select", { id: "log-source", value: model.logSource, onchange: event => ui.filter("logSource", event.target.value) },
    [["", "全部"], ...Object.entries(sources)].map(([value, title]) => h("option", { value }, title)));
  const size = h("select", { id: "log-page-size", value: model.logPageSize, onchange: event => ui.filter("logPageSize", Number(event.target.value)) },
    [50, 100, 200].map(value => h("option", { value }, `${value} 条`)));
  const from = h("input", { id: "log-from", type: "datetime-local", value: model.logFromInput || "", oninput: event => { model.logFromInput = event.target.value; } });
  const to = h("input", { id: "log-to", type: "datetime-local", value: model.logToInput || "", oninput: event => { model.logToInput = event.target.value; } });
  const filterError = h("p", { class: "log-filter-error", "data-log-filter-error": "", role: "alert", hidden: true });
  const label = (text, input) => h("div", { class: "log-filter" }, h("label", { for: input.id }, text), input);
  const timeSummary = h("summary", { "data-log-time-toggle": "" }, "时间范围");
  const timeRange = h("details", { class: "log-time-range", "data-log-time-range": "" }, timeSummary,
    h("div", { class: "log-time-panel" },
      label("开始时间", from), label("结束时间", to), filterError,
      h("div", { class: "log-filter-actions" }, button("应用时间范围", ui.applyTime, "ghost compact", false, { "data-log-apply-time": "" }), button("清除时间", () => { from.value = ""; to.value = ""; ui.clearTime(); }, "ghost compact", false, { "data-log-reset-time": "" })),
    ),
  );
  const pause = button("暂停日志刷新", ui.pause, "ghost compact", false, { "data-log-pause": "" });
  const pending = h("div", { class: "log-pending", "data-log-pending": "", hidden: true, role: "status" },
    h("span", { "data-log-pending-text": "" }), button("查看最新日志", ui.latest, "ghost compact", false));
  const notices = h("div", { class: "log-notices", "data-log-notices": "" });
  const body = h("tbody");
  const table = h("table", { class: "log-table", "data-log-table": "" },
    h("thead", {}, h("tr", {}, ["时间", "级别", "来源", "消息", "结构化字段"].map(title => h("th", { scope: "col" }, title)))), body);
  const viewport = h("div", { class: "runtime-logs", id: "runtime-logs", tabindex: 0, "aria-label": "运行日志列表" }, table);
  const empty = h("div", { class: "log-empty", hidden: true }, h("strong", {}, "暂无匹配的运行日志"), h("p", {}, "管理服务启动、接管启停与失败过程会记录在这里。可调整筛选查看。"));
  const older = button("较旧", ui.older, "ghost compact", true, { "data-log-older": "" });
  const newer = button("较新", ui.newer, "ghost compact", true, { "data-log-newer": "" });
  const latest = button("回到最新", ui.latest, "ghost compact", false, { "data-log-latest": "" });
  const pageStatus = h("span", { class: "log-page-status", "data-log-page-status": "", role: "status" });
  const root = h("section", { class: "diagnostics-root", "data-diagnostics-root": "" },
    toolArea,
    h("section", { class: "diagnostics-logs", "aria-label": "运行日志" },
      h("div", { class: "log-heading" }, h("h2", {}, "运行日志"), h("small", {}, "主机与辅助进程日志 · 内存保留 · 凭据脱敏")),
      h("div", { class: "log-filters", "data-log-filters": "" },
        label("最低级别", level), label("来源", source), label("每页", size),
        timeRange,
      ),
      h("div", { class: "log-toolbar" }, h("small", { class: "muted" }, "暂停仅停止刷新，不影响日志采集。"), h("div", { class: "button-row" }, pause, button("刷新日志", ui.refresh, "ghost compact", false))),
      pending, notices, viewport, empty,
      h("div", { class: "log-pagination" }, pageStatus, h("div", { class: "button-row" }, older, newer, latest)),
    ),
  );

  function rowFor(record) {
    const id = String(record.id);
    let value = rows.get(id);
    if (!value) {
      const fields = h("details", { "data-log-fields": id }, h("summary"), h("pre"), h("div", { class: "log-full-message" }));
      const cells = [h("td", { class: "log-time" }), h("td", { class: "log-level" }), h("td", { class: "log-source" }), h("td", { class: "log-message" }), h("td", { class: "log-attrs" }, fields)];
      value = { node: h("tr", { "data-log-id": id }, cells), cells, fields, signature: "" };
      rows.set(id, value);
    }
    const signature = JSON.stringify(record);
    if (value.signature !== signature) {
      const level = String(record.level || "INFO").toLowerCase();
      value.node.className = `log-row log-level-${["error", "warn", "debug", "info"].includes(level) ? level : "info"}`;
      const date = new Date(record.time);
      value.cells[0].textContent = Number.isFinite(date.valueOf()) ? date.toLocaleTimeString("zh-CN", { hour12: false }) + "." + String(date.getMilliseconds()).padStart(3, "0") : "—";
      value.cells[0].title = time(record.time);
      value.cells[1].textContent = record.level || "INFO";
      value.cells[2].textContent = sources[record.source] || record.source || "—";
      value.cells[3].textContent = record.message || "";
      value.cells[3].title = record.message || "";
      const attrs = record.attrs || {};
      const preview = logFieldPreview(attrs);
      value.fields.hidden = Object.keys(attrs).length === 0 && !/[\r\n]/.test(record.message || "") && (record.message || "").length < 100;
      value.fields.querySelector("pre").textContent = JSON.stringify(attrs);
      value.fields.querySelector("summary").textContent = preview.text || "查看完整消息";
      value.fields.querySelector("summary").title = preview.full || record.message || "";
      value.fields.querySelector(".log-full-message").textContent = record.message || "";
      value.signature = signature;
    }
    return value.node;
  }
  function update() {
    root.querySelector("[data-new-diagnostic]").disabled = !ui.canManage();
    const payloads = ui.tools();
    for (const tool of tools) {
      const payload = payloads[tool.key];
      const signature = payload?.textContent || "";
      if (tool.signature !== signature && !tool.body.contains(document.activeElement)) {
        tool.body.replaceChildren(...(payload ? [...payload.children] : []));
        tool.signature = signature;
      }
      for (const control of tool.body.querySelectorAll("button[data-diagnostic-write]")) control.disabled = !ui.canManage();
    }
    pause.textContent = model.logPaused ? "继续日志刷新" : "暂停日志刷新";
    const timeActive = Boolean(model.logFrom || model.logTo);
    const timeLabel = timeActive ? "时间范围 · 已应用" : "时间范围";
    if (timeSummary.textContent !== timeLabel) timeSummary.textContent = timeLabel;
    timeRange.classList.toggle("active", timeActive);
    filterError.hidden = !model.logFilterError;
    filterError.textContent = model.logFilterError || "";
    const errors = [model.logError && `日志暂不可用：${model.logError}`, model.logPage?.helper?.error && `辅助进程日志暂不可用：${model.logPage.helper.error}`, model.logPage?.gap && "部分旧日志已过期，保留记录不连续。"].filter(Boolean);
    if (notices.textContent !== errors.join("")) notices.replaceChildren(...errors.map(message => h("p", { class: "log-notice", role: "status" }, message)));
    pending.hidden = !model.logPendingCount;
    pending.querySelector("[data-log-pending-text]").textContent = `有 ${model.logPendingCount || 0} 条新日志，当前阅读位置已保留。`;
    const navigating = model.logLoading && model.logNeedsPage;
    older.disabled = navigating || !model.logs.length || !model.logHasOlder;
    newer.disabled = navigating || !model.logHistory.length;
    latest.disabled = navigating;
    pageStatus.textContent = `${model.logHistorical ? "历史页" : "最新页"} · ${model.logs.length} 条${model.logPaused ? " · 已暂停刷新" : ""}${model.logLoading ? " · 加载中" : ""}${model.logPage?.dropped ? ` · 主机已淘汰 ${model.logPage.dropped} 条` : ""}`;
    let anchor = body.firstChild;
    const keep = new Set();
    for (const record of [...model.logs].reverse()) {
      const node = rowFor(record);
      keep.add(node);
      if (node !== anchor) body.insertBefore(node, anchor);
      anchor = node.nextSibling;
    }
    for (const node of [...body.children]) if (!keep.has(node)) node.remove();
    // The host ring has at most 1000 records. Bound cached DOM independently.
    if (rows.size > 1200) for (const [id, value] of rows) { if (!keep.has(value.node)) rows.delete(id); if (rows.size <= 1000) break; }
    empty.hidden = model.logs.length > 0;
    viewport.hidden = model.logs.length === 0;
  }
  return { root, update, resetScroll: () => { viewport.scrollTop = 0; }, reading: () => viewport.scrollTop > 8 || Boolean(viewport.querySelector("details[open]")) || Boolean(root.querySelector("[data-log-filters]")?.contains(document.activeElement)) };
}
