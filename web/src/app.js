import {
  ApiError,
  bootstrap,
  endpoints,
  normalizeFlow,
  normalizeTraffic,
  request,
  setSession,
  targetWithPort,
  flowQueryChunks,
  exactRuleTarget,
} from "./api.js";
import { aggregatePaths, bytes, nativePaths, renderSankey } from "./graph.js";

const pages = [
  ["home", "首页", "◈", "OVERVIEW", "看清流量，掌握每一次连接。"],
  [
    "connections",
    "连接",
    "⇄",
    "CONNECTIONS",
    "从实际路径与失败阶段，理解每条连接。",
  ],
  ["inbounds", "入站", "↳", "INBOUNDS", "明确哪些流量会进入 KONE。"],
  ["outbounds", "出站", "↗", "OUTBOUNDS", "选择可信出口，并了解它的协议能力。"],
  ["rules", "规则", "≡", "ROUTING", "按顺序决定每个目标的出站策略。"],
  ["dns", "DNS", "◎", "DNS & RESOLVERS", "区分真实解析、虚拟地址与业务连接。"],
  [
    "diagnostics",
    "诊断",
    "⌁",
    "DIAGNOSTICS",
    "用有限、独立的探测寻找连接失败的原因。",
  ],
  [
    "settings",
    "设置与恢复",
    "⚙",
    "SETTINGS",
    "保留管理入口，安全地控制与恢复网络。",
  ],
];
const main = document.querySelector("#main");
const model = {
  page: "home",
  state: {},
  config: null,
  draft: null,
  inbound: null,
  credentialActions: {},
  outboundOrigins: [],
  dirty: false,
  busy: false,
  online: false,
  authenticated: true,
  traffic: normalizeTraffic(),
  graphPaused: false,
  graphFrozen: null,
  metric: "rate",
  direction: "total",
  protocol: "",
  graphSelection: null,
  graphSnapshot: null,
  tableQuery: "",
  tableStatus: "",
  tableProtocol: "",
  tablePage: 0,
  frozen: null,
  dns: null,
  diagnostics: [],
  sessions: [],
  lan: {},
  lastSuccess: null,
  notice: null,
  pendingTask: null,
};
const clone = (value) => JSON.parse(JSON.stringify(value));
const own = (object, key, fallback) => object?.[key] ?? fallback;
const list = (value) => (Array.isArray(value) ? value : []);
const label = (value) =>
  value === undefined || value === null || value === ""
    ? "未知"
    : String(value);
const time = (value) => {
  if (!value) return "尚无记录";
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? String(value)
    : date.toLocaleString("zh-CN", { hour12: false });
};
const role = () => model.state.role || model.state.session?.role || "read";
const canManage = () =>
  ["manage", "admin", "owner", "local"].includes(role()) &&
  model.online &&
  !model.busy;
const runtime = () =>
  model.state.data_state ||
  model.state.state ||
  model.state.engine?.state ||
  "idle";
const running = () => ["running", "degraded"].includes(runtime());
const stateLabels = {
  idle: "尚未接管",
  stopped: "尚未接管",
  ready: "尚未接管",
  paused: "已暂停接管",
  running: "正在接管",
  degraded: "部分连接异常",
  starting: "正在启用",
  stopping: "正在停用",
  pausing: "正在暂停",
  preflight: "预检中",
  error: "需要处理",
  recovery_failed: "恢复失败",
  recovery_required: "等待恢复确认",
  invalid_config: "配置待修复",
};
const statusLabels = {
  not_applied: "尚未应用",
  unknown: "结果未知",
  reachable: "传输可达",
  active: "活动",
  connecting: "连接中",
  closed: "已结束",
  completed: "已结束",
  failed: "失败",
  rejected: "拒绝",
  reject: "拒绝",
  running: "运行中",
  queued: "排队中",
  cancelled: "已取消",
  expired: "已过期",
  unsupported: "不支持",
  succeeded: "已完成",
  success: "已完成",
};

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  const value = props.value;
  for (const [key, item] of Object.entries(props)) {
    if (item === undefined || item === null || key === "value") continue;
    if (key.startsWith("on"))
      node.addEventListener(key.slice(2).toLowerCase(), item);
    else if (key === "class") node.className = item;
    else if (
      key === "checked" ||
      key === "disabled" ||
      key === "hidden" ||
      key === "open" ||
      key === "required"
    )
      node[key] = Boolean(item);
    else node.setAttribute(key, item);
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false)
      node.append(
        child instanceof Node ? child : document.createTextNode(String(child)),
      );
  }
  if (value !== undefined) node.value = value;
  return node;
}
const button = (text, action, kind = "", disabled = !canManage(), props = {}) =>
  h(
    "button",
    {
      class: `button ${kind}`,
      type: "button",
      disabled,
      onclick: action,
      ...props,
    },
    text,
  );
const note = (text, kind = "") =>
  h(
    "div",
    { class: `notice ${kind}`, role: kind === "error" ? "alert" : "note" },
    text,
  );
const tag = (text, kind = "") => h("span", { class: `tag ${kind}` }, text);
const badge = (value) =>
  tag(
    statusLabels[value] || value,
    ["failed", "rejected", "reject", "error"].includes(value)
      ? "error"
      : ["active", "success", "succeeded", "running"].includes(value)
        ? "success"
        : "muted",
  );
const empty = (title, text, action) =>
  h(
    "div",
    { class: "empty-state" },
    h("h3", {}, title),
    h("p", {}, text),
    action,
  );
const card = (title, description, ...children) =>
  h(
    "section",
    { class: "card" },
    h(
      "div",
      { class: "card-head" },
      h("div", {}, h("h2", {}, title), description && h("p", {}, description)),
    ),
    ...children,
  );
const row = (name, detail, value) =>
  h(
    "div",
    { class: "panel-row" },
    h(
      "div",
      { class: "row-copy" },
      h("strong", {}, name),
      detail && h("small", {}, detail),
    ),
    h("div", { class: "row-value" }, value),
  );
const table = (headers, rows) =>
  h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: "data-table" },
      h(
        "thead",
        {},
        h(
          "tr",
          {},
          headers.map((title) => h("th", {}, title)),
        ),
      ),
      h(
        "tbody",
        {},
        rows.map((cells) =>
          h(
            "tr",
            {},
            cells.map((cell) => h("td", {}, cell)),
          ),
        ),
      ),
    ),
  );
function toast(message, kind = "") {
  const node = h("div", { class: `toast ${kind}` }, message);
  document.querySelector("#toast-region").append(node);
  setTimeout(() => node.remove(), 6500);
}
function notice(message, kind = "") {
  model.notice = { message, kind };
  const place = document.querySelector("#page-notice");
  if (place) place.replaceChildren(note(message, kind));
}
function isConflict(error) {
  return error.status === 409 || error.status === 412;
}
function failure(error) {
  if (error.status === 401) {
    model.authenticated = false;
    model.online = false;
    render();
    return;
  }
  const message = isConflict(error)
    ? error.details?.code === "geoip"
      ? "GeoIP 数据或设置版本已变化，请刷新后重新核对待导入文件。"
      : "配置已被其他页面或文件修改。请重新加载并比较后再保存，你的草稿仍保留。"
    : error.message;
  notice(message, "error");
  toast(message, "error");
  if (isConflict(error)) model.versionConflict = true;
}
async function action(work, success) {
  if (!canManage()) return;
  model.busy = true;
  updateShell();
  try {
    const result = await work();
    if (success) toast(success);
    await refreshState();
    return result;
  } catch (error) {
    failure(error);
  } finally {
    model.busy = false;
    renderPreserving();
  }
}
function pageHeader(actions = []) {
  const page = pages.find((item) => item[0] === model.page) || pages[0];
  return h(
    "div",
    { class: "page-head" },
    h(
      "div",
      {},
      h("div", { class: "eyebrow" }, page[3]),
      h("h1", {}, page[1]),
      h("p", { class: "page-subtitle" }, page[4]),
    ),
    h("div", { class: "head-actions" }, actions),
  );
}
function field(
  title,
  value,
  onChange,
  {
    id,
    hint,
    type = "text",
    options,
    disabled = !canManage(),
    wide = false,
    min,
    max,
    placeholder,
    autocomplete = "off",
  } = {},
) {
  const inputID = id || `field-${title}`;
  const input = options
    ? h(
        "select",
        {
          id: inputID,
          value,
          disabled,
          onchange: (event) => onChange(event.target.value),
        },
        options.map((option) =>
          typeof option === "string"
            ? h("option", { value: option }, option)
            : h(
                "option",
                { value: option.value, disabled: option.disabled },
                option.label,
              ),
        ),
      )
    : h("input", {
        id: inputID,
        type,
        value,
        disabled,
        min,
        max,
        placeholder,
        autocomplete,
        oninput: (event) =>
          onChange(
            type === "number" ? Number(event.target.value) : event.target.value,
          ),
      });
  return h(
    "div",
    { class: `field ${wide ? "wide" : ""}` },
    h("label", { for: inputID }, title),
    input,
    hint && h("small", {}, hint),
  );
}
function check(
  title,
  value,
  onChange,
  hint,
  id = title,
  disabled = !canManage(),
) {
  return h(
    "div",
    { class: "field check-field wide" },
    h("input", {
      type: "checkbox",
      checked: value,
      disabled,
      id,
      onchange: (event) => onChange(event.target.checked),
    }),
    h(
      "div",
      {},
      h("label", { for: id }, title),
      hint && h("small", { class: "block-hint" }, hint),
    ),
  );
}
function markDirty() {
  model.dirty = true;
  document
    .querySelectorAll("[data-save]")
    .forEach((node) => (node.disabled = !canManage()));
  const label = document.querySelector("#draft-status");
  if (label) label.textContent = "有未保存的修改";
}
function configSet(section, key, value) {
  model.draft[section] ||= {};
  model.draft[section][key] = value;
  markDirty();
}
function configValue(section, key, fallback = "") {
  return own(model.draft?.[section], key, fallback);
}
function configBody() {
  return {
    base_version: model.config?.version,
    config: model.draft,
    inbound: model.inbound,
    credential_actions: model.credentialActions,
  };
}
function configFooter() {
  return h(
    "div",
    {},
    model.versionConflict &&
      note(
        "已保存版本发生变化，草稿仍基于原版本；保存将继续检测冲突。可保留草稿继续检查，或显式重新加载。",
        "warning",
      ),
    h(
      "div",
      { class: "form-footer" },
      h(
        "div",
        { class: "form-version" },
        h(
          "span",
          { id: "draft-status" },
          model.dirty ? "有未保存的修改" : "当前草稿已保存",
        ),
        h(
          "div",
          {},
          `草稿基于 ${model.config?.version ?? "—"} · 已保存 ${model.state.saved_version ?? model.config?.version ?? "—"} · 运行中 ${model.state.running_version || "尚未启用"}`,
        ),
      ),
      h(
        "div",
        { class: "button-row" },
        (model.dirty || model.versionConflict) &&
          button("重新加载设置", () =>
            dialog(
              "重新加载已保存设置",
              "这会放弃本页面保留的未保存草稿，不改变正在运行的网络。",
              note("如需保留草稿，请先核对修改内容，再取消此操作。", "warning"),
              [
                button("保留草稿", closeDialog, "ghost", false),
                button(
                  "放弃草稿并重新加载",
                  () => {
                    closeDialog();
                    action(async () => {
                      await loadConfig(true);
                      model.versionConflict = false;
                      model.notice = null;
                    }, "已加载主机保存的设置");
                  },
                  "danger",
                ),
              ],
            ),
          ),
        button("校验与预览", validateConfig),
        button(
          "保存",
          () => saveConfig(false),
          "",
          !canManage() || !model.dirty,
          { "data-save": "" },
        ),
        button(
          "保存并应用",
          () => saveConfig(true),
          "primary",
          !canManage() || !model.dirty,
          { "data-save": "" },
        ),
      ),
    ),
  );
}
async function validateConfig() {
  return action(async () => {
    const result = await endpoints.validate(configBody());
    const issues = result.issues || result.warnings || [];
    const message = result.restart_required
      ? "配置有效。该修改需要重启接管；保存不会自动中断现有连接。"
      : "配置有效。规则与出站更新将影响新连接，已有连接保留原策略。";
    notice(
      `${message}${issues.length ? ` ${issues.map((item) => item.message || item).join("；")}` : ""}`,
      result.restart_required ? "warning" : "success",
    );
    return result;
  });
}
async function saveConfig(apply) {
  return action(async () => {
    const validation = await endpoints.validate(configBody());
    if (validation.valid === false)
      throw new ApiError("配置未通过校验。", 422, validation);
    const saved = await endpoints.save(configBody());
    model.config = saved.config
      ? saved
      : { ...model.config, ...saved, config: clone(model.draft) };
    model.draft = clone(model.config.config || model.draft);
    model.dirty = false;
    model.credentialActions = {};
    model.versionConflict = false;
    if (apply && !validation.restart_required) {
      try {
        await watchOperation(
          await endpoints.apply({ version: model.config.version }),
        );
        notice(
          "设置已保存并应用。新连接使用新策略，已有连接保持原策略。",
          "success",
        );
      } catch (error) {
        notice(
          `设置已保存，但未成功应用：${error.message}。原运行配置保持不变。`,
          "error",
        );
      }
    } else
      notice(
        validation.restart_required
          ? "已保存，等待你确认重启接管。现有连接未被中断。"
          : "已保存。点击“应用已保存设置”后才会改变新连接策略。",
        validation.restart_required ? "warning" : "success",
      );
    await loadConfig(false);
    render();
  }, "设置已保存");
}
async function loadConfig(force = false) {
  const document = await endpoints.config();
  if (!force && model.dirty) {
    if (document.version !== model.config?.version)
      model.versionConflict = true;
    return;
  }
  model.config = document;
  if (force || !model.dirty) {
    model.draft = clone(document.config || {});
    model.inbound = clone(
      document.inbound || { id: "tun-main", name: "TUN", enabled: false },
    );
    model.outboundOrigins = list(document.config?.outbounds).map(
      (outbound) => outbound.name,
    );
    model.credentialActions = {};
    model.dirty = false;
  }
}
function updateShell() {
  const status = document.querySelector("#runtime-status");
  const state = runtime();
  status.className = `status ${model.online && running() ? "running" : ["starting", "stopping", "preflight", "pausing"].includes(state) ? "working" : !model.online || ["error", "recovery_failed", "invalid_config"].includes(state) ? "error" : ""}`;
  status.replaceChildren(
    h("i"),
    model.online ? stateLabels[state] || state : "状态未知",
  );
  document.querySelector("#host-label").textContent =
    model.state.host?.name ||
    (typeof model.state.host === "string" ? model.state.host : "") ||
    "本机控制台";
  document.querySelector("#session-role").textContent = [
    "manage",
    "admin",
    "owner",
    "local",
  ].includes(role())
    ? "管理会话"
    : "只读会话";
  const toggle = document.querySelector("#lifecycle-toggle");
  toggle.textContent = model.busy
    ? "处理中…"
    : running()
      ? "暂停接管"
      : "启用接管";
  toggle.disabled =
    !canManage() ||
    ["starting", "stopping", "pausing", "preflight"].includes(state);
  const banner = document.querySelector("#connection-banner");
  let text = !model.online
    ? `管理连接中断，当前状态未知。最后更新：${time(model.lastSuccess)}。写操作暂不可用。`
    : model.state.config_error ||
      model.state.last_error ||
      model.state.error ||
      "";
  if (
    !text &&
    model.state.saved_version &&
    model.state.running_version &&
    model.state.saved_version !== model.state.running_version
  )
    text = "已保存设置与运行中设置不同。请在设置页查看待应用变更。";
  banner.hidden = !text;
  banner.textContent = text;
  banner.className = `banner ${!model.online || model.state.last_error ? "error" : ""}`;
  document.querySelector("#updated-at").textContent = model.lastSuccess
    ? `管理状态更新时间 ${time(model.lastSuccess)}`
    : "等待数据";
  document.querySelectorAll(".nav-link").forEach((node) => {
    const active = node.dataset.page === model.page;
    node.classList.toggle("active", active);
    if (active) node.setAttribute("aria-current", "page");
    else node.removeAttribute("aria-current");
  });
}
async function refreshState() {
  try {
    model.state = await endpoints.state();
    setSession(model.state);
    model.online = true;
    model.authenticated = true;
    model.lastSuccess = new Date().toISOString();
    updateShell();
  } catch (error) {
    model.online = false;
    if (error.status === 401) model.authenticated = false;
    updateShell();
    throw error;
  }
}
async function lifecycle(actionName) {
  if (actionName === "start") {
    return action(async () => {
      const preflight = await endpoints.lifecycle("preflight");
      if (
        preflight.ready === false ||
        preflight.ok === false ||
        preflight.valid === false ||
        preflight.blockers?.length
      ) {
        showResult("启用预检", preflight);
        return;
      }
      const result = await watchOperation(await endpoints.lifecycle("start"));
      showResult("启用接管", result);
    });
  }
  return action(async () => {
    const result = await watchOperation(await endpoints.lifecycle(actionName));
    showResult(actionName === "pause" ? "暂停接管" : "运行操作", result);
  });
}
async function watchOperation(operation) {
  const completed = (operation) => {
    if (
      operation.error ||
      ["failed", "not_applied", "canceled", "cancelled", "expired"].includes(
        operation.status,
      )
    )
      throw new ApiError(
        operation.error || statusLabels[operation.status] || "操作未完成。",
      );
    return operation;
  };
  if (!operation.id || !["running", "queued"].includes(operation.status))
    return completed(operation);
  notice("主机正在执行操作，可在诊断页查看任务结果。页面断连不会重复提交。");
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 700));
    operation = await endpoints.operation(operation.id);
    await refreshState();
    if (!["running", "queued"].includes(operation.status)) {
      completed(operation);
      notice("主机操作已完成，运行状态已刷新。", "success");
      return operation;
    }
  }
  throw new ApiError("操作仍在执行，请在诊断页查询最终结果，勿重复提交。", 0, {
    uncertain: true,
  });
}
function trafficQuery() {
  return {
    window: "1",
    metric: model.metric === "cumulative" ? "cumulative" : model.direction,
    protocol: model.protocol,
  };
}
function changeGraph(key, value) {
  model[key] = value;
  model.graphSelection = null;
  model.graphSnapshot = null;
  model.graphPaused = false;
  model.graphFrozen = null;
  refreshAll().catch(failure);
}
async function drillPath(selected, aggregation) {
  if (model.readBusy) return;
  model.readBusy = true;
  const snapshot = model.graphSnapshot;
  try {
    let result = snapshot;
    if (aggregation.native) {
      const paths = aggregation.paths.filter((path) =>
        selected.paths.includes(path.key),
      );
      const filters = paths.map((path) => path.filter || {});
      const pathIDs = [
        ...new Set(filters.flatMap((filter) => filter.path_ids || [])),
      ];
      const flowIDs = [
        ...new Set(filters.flatMap((filter) => filter.flow_ids || [])),
      ];
      const base = { anchor: aggregation.anchor };
      if (aggregation.window_start) base.since = aggregation.window_start;
      if (aggregation.window_end) base.until = aggregation.window_end;
      const queries = flowQueryChunks(base, pathIDs, flowIDs);
      const records = new Map();
      let incomplete = flowIDs.length > 5000;
      for (const query of queries) {
        const page = normalizeTraffic(await endpoints.flows(query));
        if (page.anchor_expired) throw new ApiError("所点快照已过期。", 410);
        for (const flow of page.flows) records.set(flow.id, flow);
        incomplete ||= Boolean(page.truncated || page.next_cursor);
        result ||= page;
        if (result === snapshot) result = page;
      }
      result = {
        ...result,
        total: records.size,
        next_cursor: "",
        flows: [...records.values()],
        truncated:
          incomplete ||
          (flowIDs.length > 0 && records.size < Math.min(flowIDs.length, 5000)),
      };
    }
    model.frozen = {
      snapshot: result,
      ids: aggregation.native
        ? result.flows.map((flow) => flow.id)
        : selected.flow_ids,
      label: selected.label,
      window_start: aggregation.window_start,
      window_end: aggregation.window_end,
    };
    model.tablePage = 0;
    navigate("connections");
  } catch (error) {
    notice(
      error.status === 410
        ? "所点快照明细已过期，原聚合仍保留；不会用最新连接替代。"
        : error.message,
      "error",
    );
  } finally {
    model.readBusy = false;
  }
}

async function loadOlderFlows() {
  if (model.readBusy) return;
  const current = model.frozen?.snapshot || model.traffic;
  if (!current.next_cursor || current.flows.length >= 5000) return;
  model.readBusy = true;
  try {
    const query = model.frozen?.query || { protocol: model.protocol };
    const page = normalizeTraffic(
      await endpoints.flows({
        ...query,
        anchor: current.anchor,
        cursor: current.next_cursor,
        limit: "500",
      }),
    );
    if (page.anchor_expired)
      throw new ApiError("原列表快照已过期，请显式切换实时后重试。", 410);
    const records = new Map(
      [...current.flows, ...page.flows].map((flow) => [flow.id, flow]),
    );
    const snapshot = {
      ...current,
      next_cursor: page.next_cursor,
      flows: [...records.values()],
      total: page.total,
      truncated: current.truncated || page.truncated,
    };
    model.frozen = {
      snapshot,
      ids: snapshot.flows.map((flow) => flow.id),
      query,
      label: "连接列表分页",
    };
    render();
  } catch (error) {
    notice(error.message, "error");
  } finally {
    model.readBusy = false;
  }
}
function closeDialog() {
  document.querySelector("#detail-dialog").close();
}
function dialog(title, subtitle, content, actions = []) {
  const node = document.querySelector("#detail-content");
  node.replaceChildren(
    h(
      "div",
      { class: "dialog-head" },
      h("div", {}, h("h2", {}, title), subtitle && h("p", {}, subtitle)),
      button("×", closeDialog, "ghost compact", false, {
        "aria-label": "关闭详情",
      }),
    ),
    content,
    actions.length && h("div", { class: "form-footer" }, actions),
  );
  const modal = document.querySelector("#detail-dialog");
  if (!modal.open) modal.showModal();
}
function showResult(title, result) {
  const issues = result.issues || result.checks || result.blockers;
  dialog(
    title,
    result.message ||
      (result.ready === false
        ? "预检未通过，请修复下列问题后重试。"
        : "结果来自 KONE 主机。"),
    issues
      ? h(
          "div",
          { class: "panel-list" },
          list(issues).map((item) =>
            row(
              item.name || item.id || item.code || "检查项",
              item.message || item.detail || "",
              badge(
                item.status ||
                  (item.ok === false || item.severity === "error"
                    ? "failed"
                    : item.severity === "warning"
                      ? "warning"
                      : item.ok === true
                        ? "success"
                        : item.severity || "unknown"),
              ),
            ),
          ),
        )
      : h(
          "div",
          {},
          detailPairs([
            [
              "状态",
              statusLabels[result.status] ||
                (result.ready === true ? "预检通过" : "结果可查看"),
            ],
            [
              "说明",
              result.error ||
                result.message ||
                "请以顶部运行状态和连接证据为准。",
            ],
          ]),
          h(
            "details",
            { class: "disclosure" },
            h("summary", {}, "技术详情"),
            h("pre", { class: "code-output" }, JSON.stringify(result, null, 2)),
          ),
        ),
  );
}
function detailPairs(pairs) {
  return h(
    "dl",
    { class: "detail-grid" },
    pairs.flatMap(([name, value]) => [
      h("dt", {}, name),
      h("dd", {}, label(value)),
    ]),
  );
}
function readonlyNote() {
  return canManage()
    ? null
    : note(
        model.online
          ? "当前为只读会话，可查看状态与记录；配置、诊断和启停需要管理授权。"
          : "管理连接恢复后，才能确认权限并执行操作。",
        "warning",
      );
}

function renderHome() {
  const flows = model.traffic.flows;
  const stats = model.traffic.stats;
  const historical = model.traffic.frozen || !model.online;
  const upload = Number(
    stats.upload_rate ??
      stats.UploadRate ??
      flows.reduce((sum, flow) => sum + flow.upload_rate, 0),
  );
  const download = Number(
    stats.download_rate ??
      stats.DownloadRate ??
      flows.reduce((sum, flow) => sum + flow.download_rate, 0),
  );
  const total =
    Number(
      stats.upload ??
        stats.upload_bytes ??
        flows.reduce((sum, flow) => sum + flow.upload, 0),
    ) +
    Number(
      stats.download ??
        stats.download_bytes ??
        flows.reduce((sum, flow) => sum + flow.download, 0),
    );
  const active = Number(
    stats.active ??
      flows.filter((flow) => ["active", "connecting"].includes(flow.status))
        .length,
  );
  const failed =
    stats.failed === undefined
      ? flows.filter((flow) =>
          ["failed", "rejected", "reject"].includes(flow.status),
        ).length
      : Number(stats.failed) + Number(stats.rejected || 0);
  const metricCard = (title, value, foot, glyph) =>
    h(
      "section",
      { class: "metric" },
      h(
        "div",
        { class: "metric-label" },
        title,
        h("span", { class: "metric-glyph", "aria-hidden": true }, glyph),
      ),
      h(
        "div",
        { class: "metric-value" },
        model.traffic.session_id ? value : "—",
      ),
      h(
        "div",
        { class: "metric-foot" },
        model.traffic.session_id ? foot : "等待有效主机快照",
      ),
    );
  const metrics = h(
    "div",
    { class: "metrics" },
    metricCard(
      historical ? "上次采样上传 / 下载" : "实时上传 / 下载",
      `${bytes(upload, true)} / ${bytes(download, true)}`,
      historical
        ? `保留采样 · ${time(model.traffic.at)}`
        : "当前采样窗口 · 业务载荷",
      "↕",
    ),
    metricCard("本会话累计", bytes(total), "上下行合计 · 不叠加图形连线", "◴"),
    metricCard(
      historical ? "上次采样活动连接" : "活动连接",
      active.toLocaleString(),
      historical
        ? "历史数量 · 当前状态不由旧采样推断"
        : "TCP 与 UDP · 仅进入 KONE",
      "⇄",
    ),
    metricCard(
      "失败 / 拒绝",
      failed.toLocaleString(),
      "已保留事件 · 包含零字节",
      "⌁",
    ),
  );
  const controls = h(
    "div",
    { class: "toolbar" },
    h(
      "div",
      { class: "segmented", "aria-label": "统计窗口" },
      ["rate", "cumulative"].map((metric) =>
        h(
          "button",
          {
            type: "button",
            "aria-pressed": model.metric === metric,
            onclick: () => changeGraph("metric", metric),
          },
          metric === "rate"
            ? historical ? "上次采样速率" : "实时速率"
            : "会话累计",
        ),
      ),
    ),
    h(
      "label",
      {},
      "方向",
      h(
        "select",
        {
          id: "graph-direction",
          value: model.direction,
          onchange: (event) => changeGraph("direction", event.target.value),
        },
        [
          ["total", "合计"],
          ["upload", "上传"],
          ["download", "下载"],
        ].map(([value, title]) => h("option", { value }, title)),
      ),
    ),
    h(
      "label",
      {},
      "协议",
      h(
        "select",
        {
          id: "graph-protocol",
          value: model.protocol,
          onchange: (event) => changeGraph("protocol", event.target.value),
        },
        h("option", { value: "" }, "全部"),
        h("option", { value: "tcp" }, "TCP"),
        h("option", { value: "udp" }, "UDP"),
      ),
    ),
    button(
      model.graphPaused ? "继续图形" : "暂停图形",
      () => {
        model.graphPaused = !model.graphPaused;
        model.graphFrozen = model.graphPaused ? clone(model.traffic) : null;
        render();
      },
      "ghost compact",
      false,
    ),
    button(
      model.graphZoom ? "恢复图形大小" : "放大图形",
      () => {
        model.graphZoom = !model.graphZoom;
        render();
      },
      "ghost compact",
      false,
    ),
  );
  const graphData = model.graphSelection
    ? model.graphSnapshot
    : model.graphFrozen || model.traffic;
  const aggregation =
    nativePaths(graphData?.sankey, {
      metric: model.metric,
      direction: model.direction,
    }) ||
    aggregatePaths(graphData?.flows || [], {
      metric: model.metric,
      direction: model.direction,
      protocol: model.protocol,
    });
  const graphContainer = h("div", {
    class: `graph-viewport${model.graphZoom ? " zoomed" : ""}`,
    id: "sankey",
    tabindex: 0,
    "aria-label": "可横向滚动的桑基图区域",
  });
  const selectionContainer = h("div", { id: "path-selection" });
  const selectPath = (selection) => {
    model.graphSelection = selection;
    model.graphSnapshot = clone(graphData);
    renderGraph();
    renderSelection();
  };
  function renderSelection() {
    selectionContainer.replaceChildren();
    const selected = model.graphSelection;
    if (!selected) return;
    selectionContainer.append(
      h(
        "div",
        { class: "drawer-summary" },
        h(
          "div",
          {},
          h("strong", {}, selected.label),
          h(
            "p",
            {},
            `${bytes(selected.value, model.metric === "rate")} · ${selected.count ?? selected.flow_ids.length} 条连接 · 占筛选总量 ${aggregation.total ? ((selected.value / aggregation.total) * 100).toFixed(1) : 0}%`,
          ),
        ),
        h(
          "div",
          { class: "button-row" },
          button(
            "查看连接",
            () => drillPath(selected, aggregation),
            "primary compact",
            false,
          ),
          button(
            "清除选择",
            () => {
              model.graphSelection = null;
              model.graphSnapshot = null;
              render();
            },
            "ghost compact",
            false,
          ),
        ),
      ),
    );
  }
  function renderGraph() {
    renderSankey(graphContainer, aggregation, {
      onSelect: selectPath,
      selected: model.graphSelection,
      metric: model.metric,
    });
  }
  renderGraph();
  renderSelection();
  const pathList = h(
    "details",
    { class: "disclosure" },
    h("summary", {}, "同口径路径列表"),
    table(
      ["完整路径", model.metric === "rate" ? "速率" : "累计字节", "连接数", ""],
      aggregation.paths.map((path) => [
        path.nodes.map((node) => node.label).join(" → "),
        bytes(path.value, model.metric === "rate"),
        path.count,
        button(
          "选择路径",
          () => {
            selectPath({
              label: path.nodes.map((node) => node.label).join(" → "),
              paths: [path.key],
              flow_ids: path.flow_ids,
              count: path.count,
              value: path.value,
              anchor: aggregation.anchor,
            });
            selectionContainer.scrollIntoView({ block: "nearest" });
          },
          "ghost compact",
          false,
        ),
      ]),
    ),
  );
  const graphCard = h(
    "section",
    { class: "card" },
    h(
      "div",
      { class: "card-head" },
      h(
        "div",
        {},
        h("h2", {}, "流量经过哪里"),
        h("p", {}, "实际入站 → 规则 / 策略 → 实际出站 → 最终业务目的"),
      ),
      controls,
    ),
    graphContainer,
    selectionContainer,
    pathList,
    h(
      "div",
      { class: "graph-note" },
      h(
        "span",
        {},
        model.traffic.frozen
          ? `接管已停止，显示保留采样 · ${time(graphData?.at)}`
          : model.graphPaused && !model.online
          ? "图形已固定；管理连接中断，当前接管状态未知。"
          : model.graphPaused
          ? "图形已暂停；实时计数与接管继续运行。"
          : `同一业务量按每层各投影一次 · ${model.metric === "rate" ? "B/s" : "字节"} · ${time(graphData?.at)}`,
      ),
      h(
        "span",
        {},
        `明细丢弃 ${model.traffic.dropped}${graphData?.sankey?.truncated ? " · 聚合已截断" : ""}`,
      ),
    ),
  );
  const failures = flows
    .filter(
      (flow) => flow.error || ["failed", "rejected"].includes(flow.status),
    )
    .slice(-4)
    .reverse();
  const nextSteps = h(
    "div",
    { class: "panel-list" },
    [
      [
        "01",
        "配置需要的出站",
        "没有代理也可使用内置直连；代理不可用不会阻断管理。",
        "outbounds",
      ],
      [
        "02",
        "确认接管范围",
        "选择性接管或全 IPv4 接管，启用前先完成预检。",
        "inbounds",
      ],
      [
        "03",
        "从证据调整规则",
        "观察失败原因，独立诊断，再为精确目标建立规则。",
        "rules",
      ],
    ].map(([number, title, text, page]) =>
      h(
        "a",
        { class: "step-row", href: `#${page}` },
        h("span", { class: "step-number" }, number),
        h("div", {}, h("strong", {}, title), h("p", {}, text)),
      ),
    ),
  );
  return [
    model.traffic.frozen &&
      note(
        `接管已停止：这里是 ${time(model.traffic.at)} 的保留快照，速率与活动数量属于停止前的采样，不会继续实时更新。`,
        "warning",
      ),
    metrics,
    graphCard,
    h(
      "div",
      { class: "split-grid" },
      card(
        "需要关注",
        "失败是排障线索，不自动等于应该代理。",
        failures.length
          ? h(
              "div",
              { class: "panel-list" },
              failures.map((flow) =>
                row(
                  flow.target,
                  flow.error || flow.stage || "策略拒绝",
                  button("详情", () => showFlow(flow), "ghost compact", false),
                ),
              ),
            )
          : empty("暂未发现失败事件", "已观察的失败与策略拒绝会保留在这里。"),
      ),
      card("从这里开始", "先让管理可用，再按需启用接管。", nextSteps),
    ),
  ];
}

function renderConnections() {
  let flows = model.frozen
    ? model.frozen.snapshot.flows.filter((flow) =>
        model.frozen.ids.includes(flow.id),
      )
    : model.traffic.flows;
  const query = model.tableQuery.toLowerCase();
  flows = flows.filter(
    (flow) =>
      (!query ||
        `${flow.target} ${flow.source} ${flow.outbound} ${flow.rule}`
          .toLowerCase()
          .includes(query)) &&
      (!model.tableStatus || flow.status === model.tableStatus) &&
      (!model.tableProtocol || flow.protocol === model.tableProtocol),
  );
  flows = [...flows].sort(
    (a, b) =>
      String(b.started_at).localeCompare(String(a.started_at)) ||
      a.id.localeCompare(b.id),
  );
  const pageSize = 30;
  const pageCount = Math.max(1, Math.ceil(flows.length / pageSize));
  model.tablePage = Math.min(model.tablePage, pageCount - 1);
  const table = h(
    "table",
    { class: "data-table" },
    h(
      "thead",
      {},
      h(
        "tr",
        {},
        [
          "状态",
          "目标 / 来源",
          "协议",
          "实际出站 / 规则",
          "上传 / 下载",
          "开始时间",
          "",
        ].map((title) => h("th", {}, title)),
      ),
    ),
    h(
      "tbody",
      {},
      flows
        .slice(model.tablePage * pageSize, (model.tablePage + 1) * pageSize)
        .map((flow) =>
          h(
            "tr",
            {},
            h("td", {}, badge(flow.status)),
            h(
              "td",
              {},
              h("span", { class: "target-cell" }, flow.target),
              h("small", { class: "cell-sub" }, flow.source),
            ),
            h("td", {}, flow.protocol.toUpperCase()),
            h(
              "td",
              {},
              h("span", {}, flow.outbound),
              h("small", { class: "cell-sub" }, flow.rule),
            ),
            h("td", {}, `${bytes(flow.upload)} / ${bytes(flow.download)}`),
            h("td", {}, time(flow.started_at)),
            h(
              "td",
              {},
              button("详情", () => showFlow(flow), "ghost compact", false),
            ),
          ),
        ),
    ),
  );
  const tools = h(
    "div",
    { class: "table-tools" },
    h("input", {
      type: "search",
      id: "connection-search",
      placeholder: "搜索目标、来源、出站或规则",
      "aria-label": "搜索连接",
      value: model.tableQuery,
      oninput: (event) => {
        model.tableQuery = event.target.value;
        model.tablePage = 0;
        renderPreserving();
      },
    }),
    h(
      "select",
      {
        id: "connection-status",
        "aria-label": "连接状态",
        value: model.tableStatus,
        onchange: (event) => {
          model.tableStatus = event.target.value;
          model.tablePage = 0;
          render();
        },
      },
      [
        ["", "所有状态"],
        ["active", "活动"],
        ["connecting", "连接中"],
        ["closed", "已结束"],
        ["failed", "失败"],
        ["rejected", "拒绝"],
      ].map(([value, title]) => h("option", { value }, title)),
    ),
    h(
      "select",
      {
        id: "connection-protocol",
        "aria-label": "连接协议",
        value: model.tableProtocol,
        onchange: (event) => {
          model.tableProtocol = event.target.value;
          model.tablePage = 0;
          render();
        },
      },
      [
        ["", "所有协议"],
        ["tcp", "TCP"],
        ["udp", "UDP"],
      ].map(([value, title]) => h("option", { value }, title)),
    ),
  );
  return [
    model.frozen &&
      note(
        `固定观察快照：${model.frozen.label} · ${time(model.frozen.window_start || model.frozen.snapshot.at)}${model.frozen.window_end ? ` 至 ${time(model.frozen.window_end)}` : ""}。页面保留所点样本；计数为明细当前值，不将新连接混入。`,
      ),
    model.frozen?.snapshot.truncated &&
      note(
        "部分原始明细已过期、超出保留容量或界面 5000 条展示上限。保留原聚合证据，不用新连接补位。",
        "warning",
      ),
    model.frozen &&
      button(
        "切换实时",
        () => {
          model.frozen = null;
          render();
        },
        "ghost",
        false,
      ),
    card(
      "连接记录",
      "只显示已保留、实际进入 KONE 的业务流量；域名与进程缺失时保持未知。",
      tools,
      h(
        "div",
        { class: "search-summary" },
        `当前筛选 ${flows.length} 条 · 已载入 ${(model.frozen?.snapshot || model.traffic).flows.length} 条 / 保留 ${(model.frozen?.snapshot || model.traffic).total ?? model.traffic.flows.length} 条；筛选作用于已载入记录${model.traffic.dropped ? ` · ${model.traffic.dropped} 条明细因容量限制未保留` : ""}`,
      ),
      flows.length
        ? h("div", { class: "table-wrap" }, table)
        : empty(
            "没有符合条件的连接",
            "可尝试调整筛选；DNS 请求不代表业务连接已经进入 KONE。",
          ),
      h(
        "div",
        { class: "pagination" },
        h("span", {}, `第 ${model.tablePage + 1} / ${pageCount} 页`),
        h(
          "div",
          { class: "button-row" },
          button(
            "上一页",
            () => {
              model.tablePage--;
              render();
            },
            "ghost compact",
            model.tablePage === 0,
          ),
          button(
            "下一页",
            () => {
              model.tablePage++;
              render();
            },
            "ghost compact",
            model.tablePage >= pageCount - 1,
          ),
        ),
      ),
      !model.frozen?.window_start &&
        (model.frozen?.snapshot || model.traffic).next_cursor &&
        button("固定快照并加载更早记录", loadOlderFlows, "ghost", false),
    ),
  ];
}
function showFlow(flow) {
  const frozen = clone(flow);
  const content = h(
    "div",
    {},
    h(
      "div",
      { class: "path-chips" },
      [frozen.inbound, frozen.rule, frozen.outbound, frozen.target].flatMap(
        (part, index) =>
          index
            ? [h("b", { "aria-hidden": true }, "→"), h("span", {}, part)]
            : [h("span", {}, part)],
      ),
    ),
    frozen.error && note(frozen.error, "error"),
    detailPairs([
      ["连接标识", frozen.id],
      ["来源地址", frozen.source],
      ["请求目标", frozen.target],
      ["原始目的地址", frozen.destination],
      [
        "域名证据",
        frozen.domain_source ||
          (frozen.domain ? "有域名元数据；来源未提供" : "未观察到域名"),
      ],
      ["真实地址", frozen.real_ip || "不可得；代理可能在远端解析"],
      ["虚拟地址", frozen.virtual_ip || "未使用或未知"],
      ["期望出站", frozen.expected_outbound],
      ["实际出站", frozen.outbound],
      ["命中规则", frozen.rule],
      ["配置版本", frozen.version],
      ["失败阶段", frozen.stage || "无已记录失败"],
      ["开始时间", time(frozen.started_at)],
      ["结束时间", frozen.ended_at ? time(frozen.ended_at) : "仍活动或未结束"],
      ["上传 / 下载", `${bytes(frozen.upload)} / ${bytes(frozen.download)}`],
      [
        "进程归属",
        frozen.process_status === "matched"
          ? `${frozen.process_name || "已验证进程"} · PID ${frozen.process_pid}`
          : frozen.process_status === "remote"
            ? "来自其他设备；无本机进程归属"
            : frozen.process_reason || "未提供可靠进程归属",
      ],
      ["进程证据来源", frozen.process_source],
      [
        "进程路径",
        frozen.process_status === "matched" ? frozen.process_path : "未知",
      ],
      [
        "进程观察时间",
        frozen.process_observed_at ? time(frozen.process_observed_at) : "未知",
      ],
    ]),
  );
  dialog(
    frozen.target,
    `业务连接 · ${frozen.protocol.toUpperCase()} · ${statusLabels[frozen.status] || frozen.status}`,
    content,
    [
      button(
        "独立诊断",
        () => {
          closeDialog();
          model.diagnosticTarget =
            frozen.domain || frozen.destination || frozen.target;
          navigate("diagnostics");
        },
        "",
        !canManage(),
      ),
      button(
        "为此目标建规则",
        () => {
          closeDialog();
          addExactRule(frozen.target, frozen.protocol);
        },
        "primary",
        !canManage(),
      ),
    ],
  );
}

function renderInbounds() {
  if (!model.draft)
    return [empty("配置尚未加载", "连接恢复后可查看和编辑入站。")];
  const core = model.draft.core || {};
  return [
    readonlyNote(),
    note(
      "当前提供单个 TUN 入站。Fake-IP 按域名分配，同一域名的 UDP 也会受所选出站能力影响。",
    ),
    card(
      "TUN 接管入口",
      "保存设置不会自动启用或重启网络接管。",
      h(
        "div",
        { class: "form-grid" },
        check(
          "启用此 TUN 入口",
          Boolean(model.inbound?.enabled),
          (value) => {
            model.inbound.enabled = value;
            markDirty();
          },
          "仅将入口加入下次接管；保存后仍需由你发起“启用接管”。",
          "inbound-enabled",
        ),
        field(
          "入口名称",
          model.inbound?.name || "TUN",
          (value) => {
            model.inbound.name = value;
            markDirty();
          },
          { id: "inbound-name", hint: "管理名称，不写入额外的 TUN 配置字段。" },
        ),
        field(
          "设备名称",
          core.tun || "",
          (value) => configSet("core", "tun", value),
          {
            id: "inbound-tun",
            placeholder: "自动分配",
            hint: "指定名称必须未被其他网卡使用；macOS 使用 utunN。",
          },
        ),
        field(
          "虚拟 IPv4 网段",
          core.network || "10.192.0.1/16",
          (value) => configSet("core", "network", value),
          {
            id: "inbound-network",
            hint: "避免与 LAN、VPN、其他隧道网段冲突。",
          },
        ),
        field(
          "真实出口接口",
          core["outbound-interface"] || "",
          (value) => configSet("core", "outbound-interface", value),
          {
            id: "inbound-outbound-interface",
            placeholder: "例如 Ethernet、eth0、en0",
            hint: "全 IPv4 接管必须指定，不能是 TUN 自身。",
          },
        ),
        check(
          "接管全部 IPv4 流量",
          Boolean(core["auto-route"]),
          (value) => configSet("core", "auto-route", value),
          "添加两条捕获路由，保留原默认路由；更具体的系统路由仍优先。",
          "inbound-auto-route",
        ),
        field(
          "可选 IPv6 虚拟网段",
          core["ipv6-network"] || "",
          (value) => configSet("core", "ipv6-network", value),
          {
            id: "inbound-ipv6-network",
            placeholder: "留空关闭，例如 fd7a:203::1/120",
            disabled:
              !canManage() ||
              (!model.state.capabilities?.ipv6 && !core["ipv6-network"]),
            hint: model.state.capabilities?.ipv6
              ? "本构建支持显式启用；必须为 ULA /64..120，默认关闭。"
              : "本平台/构建不支持 IPv6 接管；保持留空，可清除已有配置。",
          },
        ),
        check(
          "接管全部 IPv6 流量",
          Boolean(core["auto-route6"]),
          (value) => configSet("core", "auto-route6", value),
          "需当前构建支持并先设置 IPv6 网段与真实出口。保存不会自动添加路由。",
          "inbound-auto-route6",
          !canManage() ||
            (!model.state.capabilities?.ipv6 && !core["auto-route6"]),
        ),
        field(
          "协议栈",
          core.stack || "system",
          (value) => configSet("core", "stack", value),
          {
            id: "inbound-stack",
            options: [
              { value: "system", label: "system · 系统 TCP + sing-tun UDP" },
              {
                value: "mixed",
                label: "mixed · 系统 TCP + gVisor UDP",
                disabled: !list(model.state.capabilities?.stacks).includes(
                  "mixed",
                ),
              },
            ],
            hint: "mixed 需要对应构建能力。更换设备、出口、栈或范围需要重启。",
          },
        ),
      ),
      configFooter(),
    ),
    card(
      "启用前检查",
      "平台、权限、设备、网段、监听和出口检查由主机执行。",
      button(
        "运行预检",
        () =>
          action(async () =>
            showResult("接管预检", await endpoints.lifecycle("preflight")),
          ),
        "primary",
      ),
      h(
        "div",
        { class: "form-section" },
        detailPairs([
          ["当前数据面", stateLabels[runtime()] || runtime()],
          ["已配置入口", model.inbound?.name || "TUN"],
          [
            "运行设备",
            model.state.device || model.state.engine?.device || "尚未创建",
          ],
          [
            "支持范围",
            model.state.capabilities?.ipv6
              ? "IPv4 TCP / UDP；IPv6 需显式配置，代理能力另行检查"
              : "IPv4 TCP / UDP；本平台暂不支持 IPv6 接管",
          ],
          ["管理服务", "暂停接管后仍保留"],
        ]),
      ),
    ),
  ];
}

function outboundNames() {
  return [
    "direct",
    "reject",
    ...list(model.draft?.outbounds).map((outbound) => outbound.name),
  ];
}
function renderOutbounds() {
  if (!model.draft) return [empty("配置尚未加载", "连接恢复后可查看出站。")];
  model.draft.outbounds ||= [];
  const editors = model.draft.outbounds.map((outbound, index) => {
    const original = model.outboundOrigins[index];
    const references = list(model.draft.rules).filter(
      (rule) => rule.outbound === outbound.name,
    ).length;
    const actions = model.credentialActions[outbound.name] || {
      action: "preserve",
      original_name: original,
    };
    const credentials = (values) => {
      model.credentialActions[outbound.name] = {
        ...(model.credentialActions[outbound.name] || actions),
        ...values,
      };
      markDirty();
    };
    return h(
      "section",
      { class: "editor-item", "data-outbound": index },
      h(
        "div",
        { class: "editor-item-head" },
        h(
          "div",
          {},
          h("h3", {}, outbound.name || "新代理"),
          h("small", {}, `${references} 条规则引用 · 代理健康需独立检测`),
        ),
        button(
          "删除",
          () => {
            if (references) {
              notice("该代理仍被规则引用。先修改引用，再删除出站。", "error");
              return;
            }
            delete model.credentialActions[outbound.name];
            model.draft.outbounds.splice(index, 1);
            model.outboundOrigins.splice(index, 1);
            markDirty();
            render();
          },
          "danger compact",
        ),
      ),
      h(
        "div",
        { class: "form-grid" },
        check(
          "启用此代理出站",
          outbound.enabled !== false,
          (value) => {
            outbound.enabled = value;
            markDirty();
          },
          "禁用后新连接明确拒绝，不直连或执行 UDP 回退；已有连接保留原快照。",
          `outbound-enabled-${index}`,
        ),
        field(
          "名称",
          outbound.name,
          (value) => {
            const previous = outbound.name;
            if (value === previous) return;
            outbound.name = value;
            model.credentialActions[value] = {
              ...model.credentialActions[previous],
              action: model.credentialActions[previous]?.action || "preserve",
              original_name: original,
            };
            delete model.credentialActions[previous];
            for (const rule of list(model.draft.rules))
              if (rule.outbound === previous) rule.outbound = value;
            markDirty();
          },
          {
            id: `outbound-name-${index}`,
            hint: "名称区分大小写；direct / reject 及其大小写变体保留。",
          },
        ),
        field(
          "代理 URL",
          outbound.url || "",
          (value) => {
            outbound.url = value;
            markDirty();
          },
          {
            id: `outbound-url-${index}`,
            placeholder: "http://127.0.0.1:8080",
            hint: "HTTP/HTTPS CONNECT、SOCKS5 或 Shadowsocks AEAD，需显式端口；SS 暂不支持插件与 2022。",
          },
        ),
        field(
          "UDP 不支持时",
          outbound["udp-fallback"] || "",
          (value) => {
            outbound["udp-fallback"] = value;
            markDirty();
          },
          {
            id: `outbound-udp-${index}`,
            options: [
              { value: "", label: "默认拒绝" },
              { value: "reject", label: "明确拒绝" },
              { value: "direct", label: "明确允许直连回退" },
            ],
            hint: "直连回退会绕过代理，仅在明确允许时选择。",
          },
        ),
        field(
          "认证信息",
          actions.action,
          (value) => {
            credentials({ action: value });
            render();
          },
          {
            id: `outbound-credentials-${index}`,
            options: [
              { value: "preserve", label: "保留现有凭据" },
              { value: "replace", label: "替换凭据" },
              { value: "clear", label: "清除凭据" },
            ],
            hint: "保存时不会把脱敏掩码当作密码；普通页面不回显现有秘密。",
          },
        ),
        actions.action === "replace" &&
          field(
            "用户名 / SS 加密方法",
            actions.username || "",
            (value) => credentials({ username: value }),
            { id: `outbound-username-${index}`, autocomplete: "username" },
          ),
        actions.action === "replace" &&
          field(
            "密码",
            actions.password || "",
            (value) => credentials({ password: value }),
            {
              id: `outbound-password-${index}`,
              type: "password",
              autocomplete: "new-password",
              hint: "仅发送到已授权 KONE 主机，不写入浏览器地址、日志或脱敏导出。",
            },
          ),
      ),
      h(
        "div",
        { class: "form-section button-row" },
        tag("TCP 代理", "success"),
        tag(
          /^(socks5|ss):/i.test(outbound.url)
            ? "原生 UDP 代理"
            : "此协议不支持 UDP",
          /^(socks5|ss):/i.test(outbound.url) ? "success" : "warning",
        ),
        tag("健康状态待诊断", "muted"),
        button(
          "诊断此出站",
          () => {
            model.diagnosticOutbound = outbound.name;
            navigate("diagnostics");
          },
          "ghost compact",
          !canManage() || outbound.enabled === false,
        ),
      ),
    );
  });
  return [
    readonlyNote(),
    h(
      "div",
      { class: "builtin-grid" },
      h(
        "div",
        { class: "builtin" },
        h("span", { class: "builtin-icon" }, "↗"),
        h(
          "div",
          {},
          h("strong", {}, "直连 · direct"),
          h("small", {}, "内置 · TCP / UDP · 连通性需诊断"),
        ),
      ),
      h(
        "div",
        { class: "builtin" },
        h("span", { class: "builtin-icon" }, "⊘"),
        h(
          "div",
          {},
          h("strong", {}, "拒绝 · reject"),
          h("small", {}, "内置 · 不连接目标 · 不执行回退"),
        ),
      ),
    ),
    card(
      "代理出站",
      "添加已有代理地址。KONE 不提供或自动寻找代理服务器。",
      h(
        "div",
        { class: "editor-list" },
        editors.length
          ? editors
          : empty("尚未配置代理", "纯直连配置可以保存并使用，无需添加代理。"),
      ),
      h(
        "div",
        { class: "form-section" },
        button("＋ 添加代理", () => {
          model.draft.outbounds.push({ name: "", url: "", "udp-fallback": "" });
          model.outboundOrigins.push(undefined);
          markDirty();
          render();
        }),
      ),
      configFooter(),
    ),
  ];
}

function addExactRule(target, protocol = "") {
  if (!canManage() || !model.draft) return;
  const exact = exactRuleTarget(target, protocol);
  if (exact.type === "IP-CIDR6" && !model.draft.core?.["ipv6-network"]) {
    notice("先在入站配置可用的 IPv6 网段，再创建 IPv6 地址规则。", "warning");
    return;
  }
  const rule = {
    ...exact,
    outbound: model.draft.outbounds?.find((outbound) => outbound.enabled !== false)?.name || "direct",
  };
  model.draft.rules ||= [];
  const duplicate = model.draft.rules.find((existing) =>
    existing.type === rule.type &&
    existing.pattern?.toLowerCase() === rule.pattern.toLowerCase() &&
    (existing.protocol || "") === (rule.protocol || "") &&
    JSON.stringify([...(existing.ports || [])].sort()) === JSON.stringify([...(rule.ports || [])].sort()),
  );
  if (duplicate) {
    navigate("rules", {
      message: "已有相同精确范围的规则，请检查或编辑现有规则；没有重复添加。",
      kind: "warning",
    });
    return;
  }
  model.draft.rules.unshift(rule);
  markDirty();
  navigate("rules", {
    message: `已在用户规则首位建立精确草稿${rule.protocol ? ` · ${rule.protocol.toUpperCase()}` : ""}${rule.ports?.length ? ` · 端口 ${rule.ports.join(",")}` : ""}，尚未保存或应用。请核对目标与出站。`,
    kind: "warning",
  });
}
function renderRules() {
  if (!model.draft) return [empty("配置尚未加载", "连接恢复后可编辑规则。")];
  model.draft.rules ||= [];
  const types = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    ...(model.draft.core?.["ipv6-network"] ? ["IP-CIDR6"] : []),
    "GEOIP",
    "FINAL",
  ];
  const editors = model.draft.rules.map((rule, index) =>
    h(
      "section",
      { class: "editor-item" },
      h(
        "div",
        { class: "editor-item-head" },
        h(
          "h3",
          {},
          h(
            "span",
            { class: "rule-order" },
            String(index + 1).padStart(2, "0"),
          ),
          ` ${rule.type} ${rule.pattern || ""}`,
        ),
        h(
          "div",
          { class: "rule-controls" },
          button(
            "↑",
            () => moveRule(index, -1),
            "ghost compact",
            !canManage() || index === 0 || rule.type === "FINAL",
            { "aria-label": `将规则 ${index + 1} 上移` },
          ),
          button(
            "↓",
            () => moveRule(index, 1),
            "ghost compact",
            !canManage() ||
              index >= model.draft.rules.length - 1 ||
              rule.type === "FINAL" ||
              model.draft.rules[index + 1]?.type === "FINAL",
            { "aria-label": `将规则 ${index + 1} 下移` },
          ),
          button(
            "删除",
            () => {
              model.draft.rules.splice(index, 1);
              markDirty();
              render();
            },
            "danger compact",
          ),
        ),
      ),
      h(
        "div",
        { class: "form-grid" },
        field(
          "匹配方式",
          rule.type,
          (value) => {
            rule.type = value;
            if (!["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"].includes(value))
              delete rule["expires-at"];
            if (value === "FINAL") {
              delete rule.pattern;
              model.draft.rules.splice(index, 1);
              model.draft.rules.push(rule);
            }
            markDirty();
            render();
          },
          { id: `rule-type-${index}`, options: types },
        ),
        rule.type !== "FINAL" &&
          field(
            "匹配内容",
            rule.pattern || "",
            (value) => {
              rule.pattern = value;
              markDirty();
            },
            {
              id: `rule-pattern-${index}`,
              hint:
                rule.type === "DOMAIN-SUFFIX"
                  ? "匹配自身及子域名，扩大作用域前请确认。"
                  : rule.type === "IP-CIDR"
                    ? "只有 IP 证据时建议单地址 /32；变更 CIDR 需要重启。"
                    : "默认优先使用精确域名，避免影响共享 IP 的其他站点。",
            },
          ),
        field(
          "目标出站",
          rule.outbound || "direct",
          (value) => {
            rule.outbound = value;
            markDirty();
          },
          { id: `rule-outbound-${index}`, options: outboundNames() },
        ),
        field(
          "协议范围",
          rule.protocol || "",
          (value) => {
            if (value) rule.protocol = value;
            else delete rule.protocol;
            markDirty();
          },
          {
            id: `rule-protocol-${index}`,
            options: [
              { value: "", label: "TCP 与 UDP" },
              { value: "tcp", label: "仅 TCP" },
              { value: "udp", label: "仅 UDP" },
            ],
          },
        ),
        field(
          "目标端口",
          list(rule.ports).join(", "),
          (value) => {
            const parts = value
              .split(",")
              .map((item) => item.trim())
              .filter(Boolean);
            rule.ports = parts.map(Number);
            markDirty();
          },
          {
            id: `rule-ports-${index}`,
            placeholder: "留空匹配所有端口",
            hint: "逗号分隔，例如 443, 8443；留空匹配全部端口。",
          },
        ),
      ),
      h(
        "details",
        { class: "disclosure", open: Boolean(rule["expires-at"]) },
        h(
          "summary",
          {},
          rule["expires-at"]
            ? `临时规则 · ${time(rule["expires-at"])}`
            : "高级：规则有效期",
        ),
        h(
          "div",
          { class: "form-grid" },
          field(
            "有效期",
            rule["expires-at"] ? "temporary" : "permanent",
            (value) => {
              if (value === "permanent") delete rule["expires-at"];
              else
                rule["expires-at"] = new Date(
                  Date.now() + 3600000,
                ).toISOString();
              markDirty();
              render();
            },
            {
              id: `rule-lifetime-${index}`,
              disabled:
                !canManage() ||
                !["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"].includes(
                  rule.type,
                ),
              options: [
                { value: "permanent", label: "永久" },
                { value: "temporary", label: "临时（默认一小时，可调整）" },
              ],
              hint: "临时规则只支持域名，不隐式移除 CIDR 路由。",
            },
          ),
          rule["expires-at"] &&
            field(
              "到期时间（当前浏览器时区）",
              (() => {
                const date = new Date(rule["expires-at"]);
                return Number.isFinite(date.valueOf())
                  ? new Date(date.valueOf() - date.getTimezoneOffset() * 60000)
                      .toISOString()
                      .slice(0, 16)
                  : "";
              })(),
              (value) => {
                const date = new Date(value);
                if (Number.isFinite(date.valueOf()))
                  rule["expires-at"] = date.toISOString();
                markDirty();
              },
              {
                id: `rule-expires-${index}`,
                type: "datetime-local",
                hint: "到期后新连接继续匹配后续规则，已有连接及 Fake-IP 映射保留。",
              },
            ),
        ),
      ),
    ),
  );
  return [
    readonlyNote(),
    note(
      "规则按顺序首个匹配生效，FINAL 必须在末尾。安全绕过优先于普通规则；应用新策略不会重写旧连接的历史。协议和端口限制控制出站选择；域名使用虚拟 IP 后，同域名其他连接也可能进入 KONE，仍按各自规则匹配。",
    ),
    card(
      "路由规则",
      "默认精确匹配。保存后检查是否需要重启，再明确应用到新连接。",
      h(
        "div",
        { class: "editor-list" },
        editors.length
          ? editors
          : empty("尚无规则", "未命中规则时使用内置 direct。"),
      ),
      h(
        "div",
        { class: "form-section button-row" },
        button("＋ 添加精确域名", () => {
          const final = model.draft.rules.findIndex(
            (rule) => rule.type === "FINAL",
          );
          model.draft.rules.splice(
            final < 0 ? model.draft.rules.length : final,
            0,
            { type: "DOMAIN", pattern: "", outbound: "direct" },
          );
          markDirty();
          render();
        }),
        button("＋ 添加最终规则", () => {
          if (model.draft.rules.some((rule) => rule.type === "FINAL")) {
            notice("已经存在最终规则。", "warning");
            return;
          }
          model.draft.rules.push({ type: "FINAL", outbound: "direct" });
          markDirty();
          render();
        }),
      ),
      configFooter(),
    ),
    card(
      "模拟一次规则匹配",
      "使用已保存版本，不发起业务连接；草稿需先保存，结果不是连通性证明。",
      h(
        "form",
        {
          id: "simulate-form",
          onsubmit: async (event) => {
            event.preventDefault();
            const data = new FormData(event.target);
            await action(async () => {
              const result = await endpoints.simulate({
                target: targetWithPort(data.get("target"), data.get("port")),
                protocol: data.get("protocol"),
              });
              showResult("规则模拟", result);
            });
          },
        },
        h(
          "div",
          { class: "button-row" },
          h("input", {
            name: "target",
            id: "simulate-target",
            placeholder: "example.com",
            required: true,
            "aria-label": "模拟目标",
            disabled: !canManage(),
          }),
          h("input", {
            name: "port",
            id: "simulate-port",
            type: "number",
            min: 1,
            max: 65535,
            value: 443,
            required: true,
            "aria-label": "模拟目标端口",
            disabled: !canManage(),
          }),
          h(
            "select",
            {
              name: "protocol",
              "aria-label": "模拟协议",
              disabled: !canManage(),
            },
            h("option", { value: "tcp" }, "TCP"),
            h("option", { value: "udp" }, "UDP"),
          ),
          h(
            "button",
            { class: "button primary", type: "submit", disabled: !canManage() },
            "模拟匹配",
          ),
        ),
      ),
    ),
  ];
}
function moveRule(index, direction) {
  const next = index + direction;
  [model.draft.rules[index], model.draft.rules[next]] = [
    model.draft.rules[next],
    model.draft.rules[index],
  ];
  markDirty();
  render();
}

function renderDNS() {
  if (!model.draft)
    return [empty("配置尚未加载", "连接恢复后可查看解析设置。")];
  const dns = model.draft.dns || {};
  const records = list(
    model.dns?.queries ||
      model.dns?.history ||
      model.dns?.events ||
      model.dns?.records,
  );
  const actual =
    model.dns?.status?.servers ||
    model.dns?.upstreams ||
    model.dns?.servers ||
    model.state.dns_servers ||
    [];
  const queryTable = table(
    ["名称 / 时间", "类型", "结果", "解析器 / 传输", "延迟", ""],
    [...records]
      .sort((a, b) =>
        String(b.time || b.at).localeCompare(String(a.time || a.at)),
      )
      .slice(0, 50)
      .map((record) => [
        h(
          "div",
          {},
          h("span", { class: "target-cell" }, record.name || record.Name),
          h(
            "small",
            { class: "cell-sub" },
            time(record.at || record.time || record.started_at),
          ),
        ),
        record.type || record.Type || record.qtype,
        record.error
          ? tag("失败", "error")
          : tag(
              record.status || record.rcode || record.cache || "未知结果",
              record.status && record.status !== "NOERROR"
                ? "warning"
                : record.cache === "hit"
                  ? "muted"
                  : "success",
            ),
        `${record.upstream || record.server || "—"} / ${record.upstream_transport || record.transport || "未知"} · ${record.resolver_interface || "接口未提供"}`,
        `${record.duration_ms ?? record.latency_ms ?? "—"} ms`,
        button(
          "详情",
          () =>
            dialog(
              record.name || "DNS 查询",
              "解析成功不等于业务访问成功。",
              detailPairs(
                Object.entries(record).map(([key, value]) => [
                  key,
                  typeof value === "object" ? JSON.stringify(value) : value,
                ]),
              ),
            ),
          "ghost compact",
          false,
        ),
      ]),
  );
  return [
    readonlyNote(),
    note(
      "DNS 查询只证明名称经过 KONE，不代表后续业务连接也进入 KONE。DoH / DoT 绕过无法凭空观察。",
    ),
    card(
      "解析设置",
      "自动模式使用本次运行发现的系统上游；不内置公共 DNS 回退。",
      h(
        "div",
        { class: "form-grid" },
        check(
          "引导本机系统 DNS",
          Boolean(dns.system),
          (value) => configSet("dns", "system", value),
          "在支持的平台使用本次接管专属的 DNS 引导，监听就绪后启用，停止先恢复；保留更具体的内网/VPN 解析域，不修改 HTTP 代理或其他设备 DNS。",
          "dns-system",
          !canManage() ||
            (!model.state.capabilities?.system_dns && !dns.system),
        ),
        field(
          "上游 DNS",
          list(dns.servers).join(", "),
          (value) =>
            configSet(
              "dns",
              "servers",
              value
                .split(/[,\n]/)
                .map((item) => item.trim())
                .filter(Boolean),
            ),
          {
            id: "dns-servers",
            placeholder: "留空使用系统 DNS",
            wide: true,
            hint: "显式地址可用逗号分隔；内网名称应使用所属 DNS，避免泄漏。",
          },
        ),
        field(
          "DNS 监听端口",
          dns["listen-port"] || 53,
          (value) => configSet("dns", "listen-port", value),
          {
            id: "dns-port",
            type: "number",
            min: 1,
            max: 65535,
            hint: "TUN 地址上的服务端口，与上游服务器端口不同。",
          },
        ),
        field(
          "Fake-IP TTL（秒）",
          dns.ttl || 600,
          (value) => configSet("dns", "ttl", value),
          { id: "dns-ttl", type: "number", min: 1 },
        ),
        field(
          "读取超时（秒）",
          dns["read-timeout"] || 5,
          (value) => configSet("dns", "read-timeout", value),
          { id: "dns-read-timeout", type: "number", min: 1, max: 300 },
        ),
        field(
          "写入超时（秒）",
          dns["write-timeout"] || 5,
          (value) => configSet("dns", "write-timeout", value),
          { id: "dns-write-timeout", type: "number", min: 1, max: 300 },
        ),
      ),
      h(
        "details",
        { class: "disclosure" },
        h("summary", {}, "缓存、记录与高级参数"),
        h(
          "div",
          { class: "form-grid" },
          field(
            "DNS 报文缓冲区",
            dns["packet-size"] || 4096,
            (value) => configSet("dns", "packet-size", value),
            { id: "dns-packet-size", type: "number", min: 512, max: 65535 },
          ),
          field(
            "查询记录上限",
            dns["history-limit"] ?? 512,
            (value) => configSet("dns", "history-limit", value),
            {
              id: "dns-history-limit",
              type: "number",
              min: 0,
              max: 10000,
              hint: "0 停止保留查询明细；不会停止 DNS 服务。",
            },
          ),
          field(
            "查询保留时间（秒）",
            dns["history-retention"] ?? 3600,
            (value) => configSet("dns", "history-retention", value),
            { id: "dns-history-retention", type: "number", min: 1, max: 86400 },
          ),
          field(
            "解析缓存上限",
            dns["cache-limit"] ?? 1024,
            (value) => configSet("dns", "cache-limit", value),
            {
              id: "dns-cache-limit",
              type: "number",
              min: 0,
              max: 10000,
              hint: "0 停用 KONE 真实解析缓存；与 Fake-IP 映射及系统 DNS 缓存不同。",
            },
          ),
        ),
      ),
      h(
        "div",
        { class: "form-section" },
        detailPairs([
          ["当前解析模式", dns.servers?.length ? "显式上游" : "系统 DNS"],
          ["本次实际服务器", list(actual).join(", ") || "尚未发现或尚未启用"],
          [
            "系统发现来源",
            model.dns?.status?.system_source || "尚未发现或使用手工上游",
          ],
          [
            "系统搜索域",
            list(model.dns?.status?.search_domains).join(", ") || "未返回",
          ],
          [
            "DNS TCP",
            model.dns?.status?.tcp
              ? "支持，与 UDP 共用解析策略"
              : "尚未运行或未提供能力",
          ],
          ["IPv6 DNS 地址", "不代表已启用 IPv6 流量接管"],
        ]),
      ),
      configFooter(),
    ),
    card(
      "按域名选择解析器",
      "最长域名后缀优先；匹配内部域名后仅使用指定上游，不回退到其他解析器。",
      h(
        "div",
        { class: "editor-list" },
        list(dns.rules).map((route, index) =>
          h(
            "div",
            { class: "editor-item" },
            h(
              "div",
              { class: "form-grid" },
              field(
                "域名后缀",
                route.suffix,
                (value) => {
                  route.suffix = value;
                  markDirty();
                },
                {
                  id: `dns-route-suffix-${index}`,
                  placeholder: "corp.example",
                  hint: ". 表示所有域名。",
                },
              ),
              field(
                "解析器出口接口",
                route.interface || "",
                (value) => {
                  if (value) route.interface = value;
                  else delete route.interface;
                  markDirty();
                },
                {
                  id: `dns-route-interface-${index}`,
                  placeholder: "留空按系统路由",
                  hint: "指定真实接口；回环解析器仍保持回环，不可指定 TUN。",
                },
              ),
              field(
                "专用解析器",
                list(route.servers).join(", "),
                (value) => {
                  route.servers = value
                    .split(",")
                    .map((item) => item.trim())
                    .filter(Boolean);
                  markDirty();
                },
                {
                  id: `dns-route-servers-${index}`,
                  placeholder: "192.168.1.1:53",
                },
              ),
            ),
            button(
              "删除解析规则",
              () => {
                dns.rules.splice(index, 1);
                markDirty();
                render();
              },
              "danger compact",
            ),
          ),
        ),
      ),
      button("＋ 添加解析规则", () => {
        model.draft.dns ||= {};
        model.draft.dns.rules ||= [];
        model.draft.dns.rules.push({ suffix: "", servers: [] });
        markDirty();
        render();
      }),
      configFooter(),
    ),
    card(
      "系统解析范围",
      "以下为运行时只读快照，自动发现的系统范围不会写成可编辑内部字段。手工规则优先，不保证复制全部应用或 VPN 策略。",
      list(model.dns?.status?.warnings).map((warning) =>
        note(warning, "warning"),
      ),
      list(model.dns?.status?.rules).filter((route) => route.automatic).length
        ? h(
            "div",
            { class: "panel-list" },
            list(model.dns.status.rules)
              .filter((route) => route.automatic)
              .map((route) =>
                row(
                  `${route.exact ? "精确" : "后缀"} ${route.suffix}`,
                  `${list(route.servers).join(", ") || "上游不可用"} · ${route.interface || "系统路由"}${route.reason ? ` · ${route.reason}` : ""}`,
                  tag(
                    route.unavailable ? "拒绝不安全回退" : "系统范围",
                    route.unavailable ? "error" : "muted",
                  ),
                ),
              ),
          )
        : empty(
            "没有自动解析范围",
            "手工上游、系统未提供范围或尚未启动时，不虚构系统搜索域/VPN 配置。",
          ),
    ),
    card(
      "查询记录",
      `仅进入 KONE 的 DNS · 已保留 ${records.length} 条 · 丢弃 ${model.dns?.status?.history_dropped || 0} 条`,
      records.length
        ? queryTable
        : empty(
            "暂无经过 KONE 的查询记录",
            "启用 DNS 服务后产生的查询、负响应和失败会显示在此。",
          ),
    ),
  ];
}

function renderDiagnostics() {
  const candidates = [
    ...new Map(
      model.traffic.flows
        .filter(
          (flow) => flow.error || ["failed", "rejected"].includes(flow.status),
        )
        .map((flow) => [flow.target, flow]),
    ).values(),
  ]
    .slice(-8)
    .reverse();
  const tasks = list(
    model.diagnostics.operations ||
      model.diagnostics.tasks ||
      model.diagnostics,
  );
  const form = h(
    "form",
    {
      id: "diagnose-form",
      onsubmit: async (event) => {
        event.preventDefault();
        const fields = new FormData(event.target);
        const target = targetWithPort(fields.get("target"), fields.get("port"));
        await action(async () => {
          const result = await endpoints.diagnose({
            target,
            tls: fields.get("tls") === "on",
            outbounds: ["direct", fields.get("outbound")].filter(
              (value, index, values) =>
                value && values.indexOf(value) === index,
            ),
          });
          model.pendingTask = result.id || result.task?.id;
          notice(
            "已创建独立诊断任务。不会重放原业务请求，也不会自动修改规则。",
            "success",
          );
          await loadPageData();
          render();
        });
      },
    },
    h(
      "div",
      { class: "form-grid" },
      h(
        "div",
        { class: "field wide" },
        h("label", { for: "diagnose-target" }, "目标域名或 IP"),
        h("input", {
          id: "diagnose-target",
          name: "target",
          value: model.diagnosticTarget || "",
          placeholder: "example.com",
          required: true,
          disabled: !canManage(),
        }),
        h(
          "small",
          {},
          "仅对已观察目标或你明确输入的目标发起有限探测，不扫描网段。",
        ),
      ),
      h(
        "div",
        { class: "field" },
        h("label", { for: "diagnose-port" }, "目标端口"),
        h("input", {
          id: "diagnose-port",
          name: "port",
          type: "number",
          min: 1,
          max: 65535,
          value: 443,
          required: true,
          disabled: !canManage(),
        }),
      ),
      h(
        "div",
        { class: "field" },
        h("label", { for: "diagnose-outbound" }, "对比出站"),
        h(
          "select",
          {
            id: "diagnose-outbound",
            name: "outbound",
            value:
              model.diagnosticOutbound ||
              model.draft?.outbounds?.[0]?.name ||
              "direct",
            disabled: !canManage(),
          },
          outboundNames()
            .filter((name) => name !== "reject")
            .map((name) => h("option", { value: name }, name)),
        ),
      ),
      h(
        "div",
        { class: "field" },
        h("label", { for: "diagnose-protocol" }, "协议"),
        h(
          "select",
          { id: "diagnose-protocol", name: "protocol", disabled: !canManage() },
          h("option", { value: "tcp" }, "TCP"),
          h(
            "option",
            { value: "udp", disabled: true },
            "UDP · 尚无独立探测能力",
          ),
        ),
      ),
      h(
        "div",
        { class: "field check-field" },
        h("input", {
          type: "checkbox",
          id: "diagnose-tls",
          name: "tls",
          disabled: !canManage(),
        }),
        h("label", { for: "diagnose-tls" }, "验证 TLS 握手（不发送业务请求）"),
      ),
    ),
    h(
      "div",
      { class: "form-section" },
      h(
        "button",
        { class: "button primary", type: "submit", disabled: !canManage() },
        "开始独立诊断",
      ),
    ),
  );
  return [
    readonlyNote(),
    note(
      "TCP 连接成功只说明该传输阶段可达，不代表应用业务成功。直连与代理都失败时，需要分别查看解析、认证和连接阶段。",
    ),
    card(
      "对比直连与代理",
      "任务在主机上运行，关闭页面不会重放、复制或取消业务请求。",
      form,
    ),
    h(
      "div",
      { class: "split-grid" },
      card(
        "待诊断目标",
        "来自已观察失败，不扫描未知目标。",
        candidates.length
          ? h(
              "div",
              { class: "panel-list" },
              candidates.map((flow) =>
                row(
                  flow.target,
                  flow.error || flow.stage,
                  button(
                    "填入目标",
                    () => {
                      model.diagnosticTarget =
                        flow.domain || flow.destination || flow.target;
                      render();
                    },
                    "ghost compact",
                    !canManage(),
                  ),
                ),
              ),
            )
          : empty("尚无失败候选", "也可在上方明确输入需要诊断的目标。"),
      ),
      card(
        "诊断与控制任务",
        "结果带时间与出站范围；应用规则是单独的操作。",
        tasks.length
          ? h(
              "div",
              { class: "panel-list" },
              tasks
                .slice(-10)
                .reverse()
                .map((task) =>
                  row(
                    task.target ||
                      task.result?.target ||
                      task.request?.target ||
                      {
                        apply: "应用设置",
                        start: "启用接管",
                        pause: "暂停接管",
                        restart: "重启接管",
                        recover: "网络恢复",
                      }[task.kind] ||
                      "诊断任务",
                    `${time(task.started_at || task.created_at)} · ${task.stage || ""}`,
                    h(
                      "div",
                      { class: "button-row" },
                      badge(task.status || task.state || "queued"),
                      button(
                        "结果",
                        () => showTask(task),
                        "ghost compact",
                        false,
                      ),
                      ["running", "queued"].includes(
                        task.status || task.state,
                      ) &&
                        button(
                          "取消",
                          () =>
                            action(
                              () => endpoints.cancel(task.id),
                              "已请求取消诊断",
                            ),
                          "danger compact",
                        ),
                    ),
                  ),
                ),
            )
          : empty(
              "尚无诊断任务",
              "发起诊断后，可在这里查看任务状态和分阶段结果。",
            ),
      ),
    ),
  ];
}
function showTask(task) {
  const target = task.target || task.result?.target || task.request?.target;
  const results = list(task.result?.results || task.results);
  dialog(
    target || "控制任务结果",
    "结果仅描述所列目标、本次网络和探测阶段，不代表应用业务成功。",
    h(
      "div",
      {},
      task.error && note(task.error, "error"),
      badge(task.status || "unknown"),
      task.result?.suggest_proxy &&
        note(
          "本次直连未成功而代理传输可达。可考虑精确目标规则，并在应用后用新业务连接验证。",
          "warning",
        ),
      results.length
        ? h(
            "div",
            { class: "panel-list" },
            results.map((result) =>
              row(
                result.outbound || "未知出站",
                `${{ target_tls: "目标 TLS", proxy_transport: "代理外层传输", proxy_auth: "代理认证", proxy_handshake: "代理握手", connect: "目标连接", dns: "DNS 解析" }[result.stage] || result.stage || "未知阶段"} · ${result.message || ""}${result.peer_kind === "proxy_endpoint" ? " · 地址证据仅为代理端点，真实业务地址未知" : ""}${result.dns_path ? ` · DNS ${result.dns_path}` : ""}`,
                h(
                  "div",
                  {},
                  badge(
                    result.status === "reachable" ? "succeeded" : result.status,
                  ),
                  h(
                    "small",
                    { class: "block-hint" },
                    `${result.duration_ms ?? "未知"} ms · ${time(result.time)}`,
                  ),
                ),
              ),
            ),
          )
        : note(
            ["running", "queued"].includes(task.status)
              ? "任务仍在主机执行，可关闭详情后查看更新。"
              : "该任务没有返回独立探测阶段。",
          ),
      h(
        "details",
        { class: "disclosure" },
        h("summary", {}, "技术证据与时间"),
        h("pre", { class: "code-output" }, JSON.stringify(task, null, 2)),
      ),
    ),
    [
      target &&
        button(
          "建立精确规则草稿",
          () => {
            closeDialog();
            addExactRule(target, "tcp");
          },
          "primary",
          !canManage(),
        ),
    ].filter(Boolean),
  );
}

function renderSettings() {
  const sessions = list(model.sessions.sessions || model.sessions);
  const network =
    model.recovery || model.state.recovery || model.state.network || {};
  return [
    readonlyNote(),
    card(
      "配置与生命周期",
      "保存、应用与接管是三个不同步骤，暂停接管会保留管理服务。",
      detailPairs([
        ["控制层", model.state.control_state || "管理可用"],
        ["数据面", stateLabels[runtime()] || runtime()],
        ["已保存版本", model.state.saved_version ?? model.config?.version],
        ["运行版本", model.state.running_version || "尚未启用"],
        ["本次会话", model.state.session_id || "尚未启用"],
        ["设置来源", model.state.config_source || "应用管理的用户设置"],
      ]),
      h(
        "div",
        { class: "form-section button-row" },
        button("预检", () =>
          action(async () =>
            showResult("预检结果", await endpoints.lifecycle("preflight")),
          ),
        ),
        button(
          "应用已保存设置",
          () =>
            action(
              async () =>
                watchOperation(
                  await endpoints.apply({ version: model.config?.version }),
                ),
              "已应用保存的设置",
            ),
          "primary",
        ),
        button(
          "重启接管",
          () =>
            dialog(
              "确认重启接管",
              "重启将中断现有业务连接。新配置启用失败时，管理入口保持可用。",
              note("请先完成预检并确认网段、真实出口和 DNS 设置。", "warning"),
              [
                button("取消", closeDialog, "ghost", false),
                button(
                  "确认重启",
                  () => {
                    closeDialog();
                    lifecycle("restart");
                  },
                  "danger",
                ),
              ],
            ),
          "danger",
          !canManage() || !running(),
        ),
        button("撤销最近配置变更", () =>
          action(async () => {
            await endpoints.undo({ base_version: model.config?.version });
            await loadConfig(true);
            render();
          }, "已保存上一份有效设置，尚未应用"),
        ),
      ),
    ),
    card(
      "导入与恢复配置",
      "导入先校验，再由你确认保存；不会自动启用接管。最近有效设置可从上方撤销恢复。",
      h(
        "div",
        { class: "button-row" },
        button("导入 TOML 设置", importConfig),
        button(
          "恢复默认设置",
          () =>
            dialog(
              "恢复默认设置",
              "将保存默认入站、DNS、规则与出站，并将 TUN 入口设为未启用。原运行中的连接不会因此自动重启。",
              note(
                "自定义规则与代理将从已保存设置中移除；需要时可撤销最近一次配置变更。",
                "warning",
              ),
              [
                button("取消", closeDialog, "ghost", false),
                button(
                  "确认保存默认设置",
                  () => {
                    closeDialog();
                    action(async () => {
                      await request("/config/defaults", "POST", {
                        base_version: model.config.version,
                      });
                      await loadConfig(true);
                      notice(
                        "默认设置已保存，TUN 入口未启用。现有接管请在上方显式暂停或应用。",
                        "warning",
                      );
                    });
                  },
                  "danger",
                ),
              ],
            ),
          "danger",
        ),
      ),
    ),
    card(
      "网络恢复",
      "只恢复 KONE 明确拥有的变更，不覆盖其他程序或用户的新设置。",
      model.state.last_error && note(model.state.last_error, "error"),
      detailPairs([
        [
          "恢复状态",
          network.required
            ? "检测到待确认记录"
            : running()
              ? "接管中"
              : "未记录恢复失败",
        ],
        ["所有权判断", network.ownership || "尚无遗留记录"],
        [
          "下一步",
          network.next_action ||
            network.message ||
            "正常暂停与退出会走同一清理路径。",
        ],
      ]),
      list(network.items).length &&
        h(
          "div",
          { class: "panel-list" },
          list(network.items).map((item) =>
            row(
              item.kind,
              `${item.identity || ""} ${item.message}`,
              badge(item.status),
            ),
          ),
        ),
      model.recoveryError && note(model.recoveryError, "error"),
      h(
        "div",
        { class: "form-section button-row" },
        button(
          "暂停接管并恢复网络",
          () => lifecycle("pause"),
          "danger",
          !canManage() || !running(),
        ),
        button(
          "检查并恢复",
          () => lifecycle("recover"),
          "",
          !canManage() || running(),
        ),
      ),
    ),
    renderGeoIP(),
    card(
      "手机与平板访问",
      "默认只在本机回环监听；局域网访问需显式开启 TLS 和会话授权。",
      renderLANSettings(),
      h(
        "div",
        { class: "form-section" },
        h("h3", {}, "已授权会话"),
        sessions.length
          ? h(
              "div",
              { class: "panel-list" },
              sessions.map((session) =>
                row(
                  session.name || session.id || "授权设备",
                  `${session.role || "read"} · 到期 ${time(session.expires || session.expires_at)}`,
                  button(
                    "撤销",
                    () =>
                      action(async () => {
                        await endpoints.revoke(session.id);
                        await loadPageData();
                        render();
                      }, "会话已撤销"),
                    "danger compact",
                    !canManage() ||
                      session.current ||
                      session.id === model.state.session_id,
                  ),
                ),
              ),
            )
          : empty(
              "尚无其他授权会话",
              "设备授权可以随时撤销；只读会话不能改设置或发起诊断。",
            ),
      ),
    ),
    card(
      "日志设置",
      "输出到主机 stderr，支持结构化文本或 JSON；更改按配置预览提示重启。",
      h(
        "div",
        { class: "form-grid" },
        field(
          "日志级别",
          configValue("general", "log-level", "info"),
          (value) => configSet("general", "log-level", value),
          { id: "log-level", options: ["debug", "info", "warn", "error"] },
        ),
        field(
          "日志格式",
          configValue("general", "log-format", "text"),
          (value) => configSet("general", "log-format", value),
          { id: "log-format", options: ["text", "json"] },
        ),
      ),
      configFooter(),
    ),
    card(
      "记录、隐私与导出",
      "记录只在本机处理，不包含业务载荷或代理密码。",
      detailPairs([
        ["连接明细容量", model.traffic.capacity ?? "尚未返回"],
        [
          "连接明细保留时间",
          model.traffic.retention_seconds
            ? `${model.traffic.retention_seconds} 秒`
            : "尚未返回",
        ],
        ["明细丢弃", model.traffic.dropped],
        [
          "记录状态",
          model.traffic.recording === false
            ? "未保留明细"
            : model.traffic.recording === true
              ? "有界内存保留"
              : "未知",
        ],
      ]),
      h(
        "div",
        { class: "button-row" },
        button("导出脱敏配置", exportData, "", !model.online),
        button(
          "清空连接与 DNS 记录及本机解析缓存",
          () =>
            dialog(
              "清空本机观察记录",
              "清空 KONE 保留的连接、DNS 查询与 KONE 解析缓存，不改变系统 DNS、接管范围或代理设置。",
              null,
              [
                button("取消", closeDialog, "ghost", false),
                button(
                  "确认清空",
                  () => {
                    closeDialog();
                    action(async () => {
                      await request("/privacy/clear", "POST", {});
                      model.traffic = normalizeTraffic();
                      model.frozen = null;
                      model.graphSelection = null;
                      model.graphSnapshot = null;
                      model.graphFrozen = null;
                      model.dns = null;
                    }, "记录已清空");
                  },
                  "danger",
                ),
              ],
            ),
          "danger",
        ),
      ),
    ),
    card(
      "关于 KONE",
      "能力以当前主机实际构建与实现为准。",
      detailPairs([
        [
          "应用版本",
          model.state.version || model.state.build?.version || "开发版本",
        ],
        ["源码版本", model.state.commit || model.state.build?.commit || "未知"],
        [
          "当前协议边界",
          model.state.capabilities?.ipv6
            ? "IPv4；可显式配置 IPv6；代理 UDP 能力由出站检查决定"
            : "IPv4 接管；代理 UDP 能力由出站检查决定",
        ],
        ["许可", "GPL-3.0-or-later；组件保留独立许可"],
        ["观察范围", "仅进入 KONE 的连接；DNS、诊断与业务分开计量"],
      ]),
    ),
  ];
}
function renderGeoIP() {
  const saved = model.geoip?.saved || {};
  const input = h("input", {
    id: "geoip-file",
    type: "file",
    accept: ".json,application/json",
    disabled: !canManage() || running(),
    onchange: (event) => {
      model.geoFile = event.target.files[0];
      model.geoHash = "";
      render();
    },
  });
  const metadata = detailPairs([
    ["已保存版本", saved.version],
    ["来源", saved.source],
    ["许可", saved.license],
    ["许可地址", saved.license_url],
    [
      "发布 / 加载时间",
      `${time(saved.published_at)} / ${time(saved.loaded_at)}`,
    ],
    ["IPv4 范围数量", saved.ranges],
    ["SHA-256", saved.sha256],
    [
      "来源声明",
      saved.provenance ||
        (saved.builtin ? "内置数据" : "由导入方提供，KONE 不认证其来源"),
    ],
  ]);
  return card(
    "GeoIP 数据",
    "从可信来源手动选择 JSON 数据文件；只解释地址归属，不代表目标可达。",
    model.geoError && note(model.geoError, "error"),
    metadata,
    h(
      "p",
      { class: "muted" },
      "内置 IPv4 归属数据：",
      h(
        "a",
        {
          href: "https://db-ip.com",
          target: "_blank",
          rel: "noopener noreferrer",
        },
        "IP Geolocation by DB-IP",
      ),
      "。IPv6 国家归属尚不支持。",
    ),
    running() &&
      note(
        "先暂停接管，才能更换或回退 GeoIP。保存后需显式启用接管加载。",
        "warning",
      ),
    model.geoip?.restart_required &&
      note("已保存数据与运行快照不同，请在暂停后显式启用接管。", "warning"),
    h(
      "div",
      { class: "form-section form-grid" },
      h(
        "div",
        { class: "field wide" },
        h("label", { for: "geoip-file" }, "GeoIP JSON 文件（上限 32 MiB）"),
        input,
        model.geoFile &&
          h(
            "small",
            {},
            `已选择：${model.geoFile.name} · ${bytes(model.geoFile.size)}`,
          ),
      ),
      field(
        "可信来源提供的 SHA-256",
        model.geoExpected || "",
        (value) => {
          model.geoExpected = value;
        },
        {
          id: "geoip-expected",
          wide: true,
          hint: "校验文件后再上传。只显示来源声明，不会自动请求数据中的 URL。",
        },
      ),
    ),
    h(
      "div",
      { class: "button-row" },
      button(
        "校验并准备更新",
        async () => {
          if (!model.geoFile || model.geoFile.size > 32 * 1024 * 1024) {
            notice("请选择不超过 32 MiB 的 GeoIP JSON 文件。", "error");
            return;
          }
          const expected = (model.geoExpected || "").trim().toLowerCase();
          if (!/^[a-f0-9]{64}$/.test(expected)) {
            notice("请填写可信来源提供的完整 SHA-256。", "error");
            return;
          }
          const data = await model.geoFile.arrayBuffer();
          const digest = [
            ...new Uint8Array(await crypto.subtle.digest("SHA-256", data)),
          ]
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");
          if (digest !== expected) {
            notice("文件 SHA-256 与预期不一致，未上传或更换数据。", "error");
            return;
          }
          const baseVersion = model.config.version;
          const baseSHA = saved.sha256;
          dialog(
            "确认更新 GeoIP",
            "校验通过。只保存该数据，不自动启用接管；新会话使用新数据，旧连接历史保持原解释。",
            detailPairs([
              ["文件", model.geoFile.name],
              ["SHA-256", digest],
              ["原版本", saved.version],
            ]),
            [
              button("取消", closeDialog, "ghost", false),
              button(
                "确认保存数据",
                () => {
                  closeDialog();
                  action(async () => {
                    model.geoip = await request("/geoip", "PUT", data, {
                      rawBody: true,
                      headers: {
                        "If-Match": String(baseVersion),
                        "X-Content-SHA256": digest,
                        "X-GeoIP-Base-SHA256": baseSHA,
                      },
                    });
                    model.geoFile = null;
                    model.geoExpected = "";
                    notice("GeoIP 已保存，下次显式启用接管时加载。", "success");
                  });
                },
                "primary",
              ),
            ],
          );
        },
        "primary",
        !canManage() || running() || Boolean(model.geoError),
      ),
      button(
        model.geoError ? "尝试恢复已保存上一版" : "回退上一份 GeoIP",
        () =>
          dialog(
            "回退 GeoIP",
            model.geoError
              ? "当前数据无法读取。主机将重新校验已保存 previous 元数据及数据文件，成功后恢复；不会猜测或自动替换成内置版。"
              : "将保存上一份有效数据，不自动启用接管。",
            detailPairs([
              ["回退版本", model.geoip?.previous?.version],
              ["SHA-256", model.geoip?.previous?.sha256],
            ]),
            [
              button("取消", closeDialog, "ghost", false),
              button(
                "确认回退数据",
                () => {
                  closeDialog();
                  action(async () => {
                    model.geoip = await request("/geoip/rollback", "POST", {
                      base_version: model.config.version,
                      base_sha256: model.geoError ? "" : saved.sha256,
                    });
                    notice(
                      "已保存上一份 GeoIP，下次显式启用接管时加载。",
                      "success",
                    );
                  });
                },
                "danger",
              ),
            ],
          ),
        "danger",
        !canManage() ||
          running() ||
          (!model.geoip?.previous && !model.geoError),
      ),
    ),
  );
}
function importConfig() {
  const text = h("textarea", {
    id: "import-toml",
    rows: 10,
    spellcheck: false,
    placeholder: "粘贴完整 TOML 配置",
    "aria-label": "待导入 TOML",
  });
  const errors = h("div", { role: "status", id: "import-result" });
  const input = h("input", {
    type: "file",
    accept: ".toml,text/plain",
    id: "import-file",
    "aria-label": "选择 TOML 文件",
    onchange: async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      if (file.size > 512 * 1024) {
        errors.replaceChildren(
          note("文件超过 512 KB，请缩小配置后导入。", "error"),
        );
        return;
      }
      text.value = await file.text();
    },
  });
  dialog(
    "导入配置",
    "仅将配置发给已授权的 KONE 主机；不会读取任意本机路径。",
    h(
      "div",
      {},
      note(
        "导出文件已脱敏；导入时仅能保留匹配现有端点的凭据。新增代理凭据需由你提供。",
      ),
      input,
      h("div", { class: "form-section" }, text),
      errors,
    ),
    [
      button("取消", closeDialog, "ghost", false),
      button(
        "校验导入",
        async () => {
          if (!text.value.trim()) {
            errors.replaceChildren(note("请先选择或粘贴 TOML 配置。", "error"));
            return;
          }
          const body = { base_version: model.config.version, toml: text.value };
          try {
            const result = await request(
              "/config/import/validate",
              "POST",
              body,
            );
            dialog(
              "确认导入设置",
              result.restart_required
                ? "配置有效。保存后需显式重启接管，当前连接不自动中断。"
                : "配置有效。保存后需显式应用到新连接或启用接管。",
              detailPairs([
                [
                  "代理数量",
                  list(result.candidate_document?.config?.outbounds).length,
                ],
                [
                  "规则数量",
                  list(result.candidate_document?.config?.rules).length,
                ],
                [
                  "导入目标版本",
                  result.candidate_document?.version || "下一配置版本",
                ],
              ]),
              [
                button("取消", closeDialog, "ghost", false),
                button(
                  "确认保存导入",
                  () => {
                    closeDialog();
                    action(async () => {
                      await request("/config/import", "POST", body);
                      await loadConfig(true);
                      notice("导入设置已保存，尚未应用。", "success");
                    });
                  },
                  "primary",
                ),
              ],
            );
          } catch (error) {
            errors.replaceChildren(note(error.message, "error"));
          }
        },
        "primary",
      ),
    ],
  );
}
function renderLANSettings() {
  const lan = model.lan;
  const owner = canManage() && !model.state.remote_session;
  const address = h("input", {
    id: "lan-address",
    type: "text",
    value: (lan.address || "").replace(/^https:\/\//, ""),
    placeholder: "192.168.1.10:9243",
    disabled: !owner,
    "aria-label": "局域网 TLS 监听地址",
  });
  return h(
    "div",
    {},
    note(
      "手机看到所连接 KONE 主机的流量，打开页面不会使手机全部业务自动经过 KONE。",
    ),
    model.state.remote_session &&
      note(
        "局域网入口、配对代码和证书下载需要在 KONE 主机本机操作。",
        "warning",
      ),
    h(
      "div",
      { class: "field" },
      h("label", { for: "lan-address" }, "局域网 TLS 监听地址"),
      address,
      h(
        "small",
        {},
        "由主机生成本地证书。需在手机显式信任证书；KONE 不自动安装根证书或开放防火墙。",
      ),
    ),
    h(
      "div",
      { class: "button-row form-section" },
      button(
        lan.enabled ? "更新局域网入口" : "开启局域网访问",
        () =>
          action(async () => {
            model.lan = await request("/access/lan", "POST", {
              enabled: true,
              address: address.value,
            });
            showResult("局域网访问", model.lan);
            await refreshState();
            render();
          }),
        "primary",
        !owner,
      ),
      lan.enabled &&
        button(
          "关闭局域网访问",
          () =>
            action(async () => {
              await request("/access/lan", "POST", { enabled: false });
              model.lan = await endpoints.lan();
              await refreshState();
              render();
            }, "局域网入口已关闭"),
          "danger",
          !owner,
        ),
      button(
        "创建只读授权码",
        () =>
          action(async () => {
            const result = await endpoints.pair({ role: "read" });
            dialog(
              "手机只读授权",
              "此代码短期有效。先信任本地主机证书，再在手机授权页输入；地址不包含长期秘密。",
              detailPairs([
                [
                  "访问地址",
                  result.address ||
                    lan.url ||
                    lan.address ||
                    "先启用局域网访问",
                ],
                ["授权代码", result.code || result.pairing_code],
                ["到期时间", time(result.expires || result.expires_at)],
                ["权限", "只读 · 不能修改配置、诊断或启停"],
              ]),
            );
          }),
        "",
        !owner || !lan.enabled,
      ),
      button(
        "创建管理授权码",
        () =>
          action(async () => {
            const result = await endpoints.pair({ role: "admin" });
            dialog(
              "手机管理授权",
              "管理会话可修改配置和启停接管，仅授权给可信设备。",
              detailPairs([
                ["访问地址", result.address || lan.url || lan.address],
                ["授权代码", result.code || result.pairing_code],
                ["到期时间", time(result.expires || result.expires_at)],
                ["权限", "管理"],
              ]),
            );
          }),
        "",
        !owner || !lan.enabled,
      ),
      owner &&
        lan.enabled &&
        h(
          "a",
          {
            class: "button ghost",
            href: "/api/v1/access/certificate",
            download: "kone-local-ca.pem",
          },
          "下载本地主机证书",
        ),
    ),
    (lan.url || lan.address) &&
      h(
        "div",
        { class: "form-section" },
        detailPairs([
          ["访问地址", lan.url || lan.address],
          ["证书指纹", lan.fingerprint || "尚未生成"],
          ["传输保护", "HTTPS · 证书需在设备上显式信任"],
        ]),
      ),
  );
}
async function exportData() {
  try {
    const result = await request("/export", "GET", undefined, {
      responseType: "text",
    });
    const url = URL.createObjectURL(
      new Blob([result], { type: "application/toml" }),
    );
    const link = h("a", {
      href: url,
      download: `kone-redacted-${new Date().toISOString().slice(0, 10)}.toml`,
    });
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    failure(error);
  }
}

function renderAuth() {
  return h(
    "section",
    { class: "card login-card" },
    h("img", { src: "/icon.svg", alt: "", width: 52, height: 52 }),
    h("h1", {}, "连接你的 KONE 主机"),
    h(
      "p",
      {},
      "管理数据只向已授权会话开放。请从主机所有者处获取短期授权代码。",
    ),
    h(
      "form",
      {
        onsubmit: async (event) => {
          event.preventDefault();
          const code = new FormData(event.target).get("pairing_code");
          const submit = event.target.querySelector("button");
          submit.disabled = true;
          try {
            await endpoints.login(code);
            model.authenticated = true;
            await refreshAll();
          } catch (error) {
            const errorNode = document.querySelector("#auth-error");
            errorNode.replaceChildren(note(error.message, "error"));
          } finally {
            submit.disabled = false;
          }
        },
      },
      h("div", { id: "auth-error" }),
      h(
        "div",
        { class: "field" },
        h("label", { for: "pairing-code" }, "授权代码"),
        h("input", {
          id: "pairing-code",
          name: "pairing_code",
          type: "password",
          autocomplete: "one-time-code",
          required: true,
          placeholder: "输入短期授权代码",
        }),
      ),
      h(
        "div",
        { class: "form-section" },
        h("button", { class: "button primary", type: "submit" }, "授权并连接"),
      ),
    ),
    h(
      "div",
      { class: "form-section" },
      h(
        "small",
        {},
        "如果你就在这台主机上，请通过 KONE 的本机入口重新打开管理页。手机需先信任本地主机证书；不需要安装 KONE 内核。",
      ),
    ),
  );
}
const renderers = {
  home: renderHome,
  connections: renderConnections,
  inbounds: renderInbounds,
  outbounds: renderOutbounds,
  rules: renderRules,
  dns: renderDNS,
  diagnostics: renderDiagnostics,
  settings: renderSettings,
};
function render() {
  updateShell();
  if (!model.authenticated) {
    main.replaceChildren(renderAuth());
    return;
  }
  const actions = [
    button("刷新", () => refreshAll().catch(failure), "ghost compact", false),
  ];
  main.replaceChildren(
    pageHeader(actions),
    h(
      "div",
      { id: "page-notice" },
      model.notice && note(model.notice.message, model.notice.kind),
    ),
    ...renderers[model.page]().filter(Boolean),
  );
}
function renderPreserving() {
  const active = document.activeElement;
  const id = active?.id;
  const start = active?.selectionStart;
  const end = active?.selectionEnd;
  const scroll = document.querySelector("#sankey")?.scrollLeft;
  render();
  if (id) {
    const replacement = document.getElementById(id);
    if (replacement && !replacement.disabled) {
      replacement.focus({ preventScroll: true });
      if (typeof start === "number" && replacement.setSelectionRange) {
        try {
          replacement.setSelectionRange(start, end);
        } catch {}
      }
    }
  }
  if (scroll) document.querySelector("#sankey")?.scrollTo({ left: scroll });
}
function navigate(page, nextNotice = null) {
  if (location.hash !== `#${page}`) {
    model.navigationNotice = nextNotice && { ...nextNotice, page };
    location.hash = page;
  } else {
    if (nextNotice) model.notice = nextNotice;
    render();
  }
}
async function loadPageData() {
  if (model.page === "dns") model.dns = await endpoints.dns();
  if (model.page === "diagnostics")
    model.diagnostics = await endpoints.diagnostics();
  if (model.page === "settings") {
    model.lan = await endpoints.lan();
    model.sessions = ["manage", "admin", "owner", "local"].includes(role())
      ? await endpoints.sessions()
      : [];
    try {
      model.geoip = await request("/geoip");
      model.geoError = null;
    } catch (error) {
      model.geoError = error.message;
      model.geoip = null;
    }
    try {
      model.recovery = await request("/recovery");
      model.recoveryError = null;
    } catch (error) {
      model.recoveryError = error.message;
    }
  }
}
async function refreshAll() {
  await refreshState();
  await loadConfig(false);
  model.traffic = normalizeTraffic(await endpoints.traffic(trafficQuery()));
  await loadPageData();
  renderPreserving();
}
function menu(open) {
  document.querySelector("#sidebar").classList.toggle("open", open);
  document.querySelector("#nav-backdrop").hidden = !open;
  document
    .querySelector("#menu-toggle")
    .setAttribute("aria-expanded", String(open));
}
document
  .querySelector("#navigation")
  .replaceChildren(
    ...pages.map(([id, title, icon]) =>
      h(
        "a",
        { class: "nav-link", href: `#${id}`, "data-page": id },
        h("span", { class: "nav-icon", "aria-hidden": true }, icon),
        title,
      ),
    ),
  );
document.querySelector("#navigation").addEventListener("click", (event) => {
  if (event.target.closest("a")) menu(false);
});
document
  .querySelector("#menu-toggle")
  .addEventListener("click", () =>
    menu(!document.querySelector("#sidebar").classList.contains("open")),
  );
document
  .querySelector("#nav-backdrop")
  .addEventListener("click", () => menu(false));
document
  .querySelector("#lifecycle-toggle")
  .addEventListener("click", () => lifecycle(running() ? "pause" : "start"));
window.addEventListener("hashchange", async () => {
  const destination = location.hash.slice(1);
  if (!pages.some((page) => page[0] === destination)) return;
  model.page = destination;
  model.notice = model.navigationNotice?.page === destination ? model.navigationNotice : null;
  model.navigationNotice = null;
  menu(false);
  render();
  if (model.online) {
    try {
      await loadPageData();
      render();
    } catch (error) {
      failure(error);
    }
  }
});
window.addEventListener("beforeunload", (event) => {
  if (model.dirty) {
    event.preventDefault();
    event.returnValue = "";
  }
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden)
    refreshAll().catch(() => {
      model.online = false;
      updateShell();
    });
});
let polling = false;
setInterval(async () => {
  if (polling || document.hidden || !model.authenticated || model.busy) return;
  polling = true;
  try {
    await refreshState();
    model.traffic = normalizeTraffic(await endpoints.traffic(trafficQuery()));
    if (["dns", "diagnostics"].includes(model.page)) await loadPageData();
    if (
      ["home", "connections", "dns", "diagnostics"].includes(model.page) &&
      !document.querySelector("#detail-dialog").open
    )
      renderPreserving();
  } catch (error) {
    model.online = false;
    updateShell();
    if (error.status === 401) {
      model.authenticated = false;
      render();
    }
  } finally {
    polling = false;
  }
}, 1500);

try {
  try {
    model.state = await bootstrap();
  } finally {
    // replaceState does not fire hashchange. Also retain the clean destination
    // when authorization fails, so a later explicit login opens the right page.
    model.page = pages.some((page) => page[0] === location.hash.slice(1))
      ? location.hash.slice(1)
      : "home";
  }
  model.online = true;
  model.authenticated = true;
  model.lastSuccess = new Date().toISOString();
  await refreshAll();
} catch (error) {
  if (error.status === 401) model.authenticated = false;
  else model.notice = { message: error.message, kind: "error" };
  model.online = false;
  render();
}
