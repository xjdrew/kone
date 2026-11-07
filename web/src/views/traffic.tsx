import { copyText } from "../browser";
import { Fragment, useDeferredValue, useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole, useWorkspaceState } from "../context";
import { api } from "../api/endpoints";
import {
  exactRule,
  flowTarget,
  pathDrill,
  formatBytes,
  formatNumber,
  groupFlows,
  timestamp,
} from "../domain";
import {
  ActionMenu,
  Button,
  ContextActions,
  Details,
  Empty,
  ErrorNotice,
  KeyValues,
  Status,
  Toggle,
  type Action,
} from "../components/ui";
import { OutboundName } from "./policy";
import { FlowGraph } from "../components/flow-graph";
import type { DNSQuery, Flow, SankeyPath, TrafficFilter, TrafficResponse } from "../model";
import styles from "./traffic.module.css";

export function useTargetActions(target: string, protocol?: string): Action[] {
  const { t } = useTranslation();
  const context = useConsole();
  const draft = (outbound: string) =>
    context.setRuleDraft({ ...exactRule(target, protocol), outbound });
  return [
    {
      id: "direct",
      label: t("traffic.direct"),
      run: () => draft("direct"),
      disabled: !context.admin || !target,
    },
    ...(context.document?.config.outbounds
      .filter((item) => item.enabled !== false)
      .map((item) => ({
        id: item.id,
        label: `${t("traffic.proxy")} ${item.name}`,
        run: () => draft(item.name),
        disabled: !context.admin || !target,
      })) ?? []),
    {
      id: "reject",
      label: t("traffic.reject"),
      run: () => draft("reject"),
      disabled: !context.admin || !target,
    },
    {
      id: "diagnose",
      label: t("traffic.diagnose"),
      run: () => context.diagnose(target),
      disabled: !context.admin || !target,
    },
    {
      id: "copy",
      disabled: !target,
      label: t("common.copy"),
      run: () => {
        void copyText(target)
          .then(() => context.notify({ key: "common.copied" }))
          .catch((error: Error) => context.notify({ key: "api.request", details: error.message }));
      },
    },
  ];
}
export function TrafficView() {
  const { t } = useTranslation();
  const search = useSearch({ from: "/traffic" });
  const navigate = useNavigate();
  const [target, setTarget] = useWorkspaceState("traffic.target", search.target);
  const filterTarget = useDeferredValue(target);
  const [protocol, setProtocol] = useWorkspaceState("traffic.protocol", "");
  const [status, setStatus] = useWorkspaceState("traffic.status", "");
  const [outbound, setOutbound] = useWorkspaceState("traffic.outbound", "");
  const [metric, setMetric] = useWorkspaceState("traffic.metric", "total");
  const [frozen, setFrozen] = useWorkspaceState<TrafficResponse | null>("traffic.frozen", null);
  const [selected, setSelected] = useWorkspaceState<Flow | null>("traffic.selected", null);
  const context = useConsole();
  const [rule, setRule] = useWorkspaceState("traffic.rule", "");
  const [since, setSince] = useWorkspaceState("traffic.since", "");
  const [until, setUntil] = useWorkspaceState("traffic.until", "");
  useEffect(() => {
    // Router drill-downs intentionally replace only the target filter.
    // oxlint-disable-next-line react/set-state-in-effect
    setTarget(search.target);
  }, [search.target, setTarget]);
  const filter: TrafficFilter & { metric: string } = {
    target: filterTarget || undefined,
    protocol: protocol || undefined,
    status: status || undefined,
    outbound: outbound || undefined,
    rule_id: rule || undefined,
    since: search.window_start || (since ? new Date(since).toISOString() : undefined),
    until: search.window_end || (until ? new Date(until).toISOString() : undefined),
    anchor: search.anchor || undefined,
    path_ids: search.path_ids || undefined,
    flow_ids: search.flow_ids || undefined,
    limit: "200",
    metric,
  };
  const result = useQuery({
    queryKey: ["traffic", filter],
    queryFn: ({ signal }) => api.traffic(filter, signal),
    enabled:
      search.view !== "dns" &&
      !frozen &&
      !(search.view === "overview" && context.workspace.has("traffic.overviewSnapshot")),
    refetchInterval: search.anchor || frozen ? false : 1500,
  });
  const overviewSnapshot =
    search.view === "overview"
      ? (context.workspace.get("traffic.overviewSnapshot") as TrafficResponse | undefined)
      : undefined;
  const data = overviewSnapshot ?? frozen ?? result.data;
  function drill(paths: SankeyPath[]) {
    if (!data) return;
    context.workspace.set("traffic.overviewSnapshot", data);
    context.workspace.set("traffic.overviewSearch", search);
    void navigate({
      to: "/traffic",
      search: {
        ...search,
        view: "connections",
        ...pathDrill(paths, data.sankey.anchor),
        target: "",
      },
    });
    setTarget("");
    setFrozen(null);
  }
  function drillGroup(flows: Flow[]) {
    if (!data) return;
    context.workspace.set("traffic.overviewSnapshot", data);
    context.workspace.set("traffic.overviewSearch", search);
    void navigate({
      to: "/traffic",
      search: {
        ...search,
        view: "connections",
        anchor: data.traffic.anchor,
        path_ids: "",
        flow_ids: flows.map((flow) => flow.id).join(","),
        target: "",
      },
    });
    setTarget("");
    setFrozen(null);
  }
  function changeFilter() {
    context.workspace.delete("traffic.overviewSnapshot");
    context.workspace.delete("traffic.overviewSearch");
    setFrozen(null);
  }
  function live() {
    changeFilter();
    void navigate({
      to: "/traffic",
      search: {
        ...search,
        anchor: "",
        path_ids: "",
        flow_ids: "",
        window_start: undefined,
        window_end: undefined,
      },
    });
  }
  return (
    <section className="view">
      <header className="viewHeader">
        <div>
          <h1>
            {t(
              search.view === "overview"
                ? "traffic.title"
                : search.view === "dns"
                  ? "dns.title"
                  : "nav.connections",
            )}
          </h1>
          <p>{t(search.view === "dns" ? "dns.subtitle" : "traffic.subtitle")}</p>
        </div>
        <div className="actions">
          {search.view !== "dns" && (
            <>
              <Status
                value={
                  search.anchor || frozen || overviewSnapshot
                    ? "frozen"
                    : result.error
                      ? "stale"
                      : "live"
                }
              />
              <Button
                onClick={() => {
                  if (search.anchor || frozen || overviewSnapshot) live();
                  else if (data) setFrozen(data);
                }}
                disabled={!data}
              >
                {t(search.anchor || frozen || overviewSnapshot ? "common.resume" : "common.freeze")}
              </Button>
            </>
          )}
        </div>
      </header>
      <nav className="viewTabs">
        {["overview", "connections", "dns"].map((view) => (
          <Link
            key={view}
            to="/traffic"
            search={
              view === "overview" && context.workspace.has("traffic.overviewSearch")
                ? (context.workspace.get("traffic.overviewSearch") as typeof search)
                : { ...search, view, target }
            }
            onClick={() => {
              const snapshot = context.workspace.get("traffic.overviewSnapshot") as
                | TrafficResponse
                | undefined;
              if (view === "overview" && snapshot) setFrozen(snapshot);
              else if (view === "connections") setFrozen(null);
            }}
            aria-current={search.view === view ? "page" : undefined}
          >
            {t(`nav.${view}`)}
          </Link>
        ))}
      </nav>
      <div className="toolbar">
        <input
          type="search"
          data-search
          aria-label={t("common.target")}
          placeholder={t("common.target")}
          value={target}
          onChange={(event) => {
            setTarget(event.target.value);
            void navigate({
              to: "/traffic",
              search: { ...search, target: event.target.value },
              replace: true,
            });
            changeFilter();
          }}
        />
        {search.view !== "dns" && (
          <>
            <select
              aria-label={t("common.protocol")}
              value={protocol}
              onChange={(event) => {
                setProtocol(event.target.value);
                changeFilter();
              }}
            >
              <option value="">
                {t("common.protocol")}: {t("common.all")}
              </option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <select
              aria-label={t("common.status")}
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                changeFilter();
              }}
            >
              <option value="">
                {t("common.status")}: {t("common.all")}
              </option>
              {["active", "closed", "failed", "rejected", "canceled"].map((value) => (
                <option key={value} value={value}>
                  {t(`traffic.${value}`)}
                </option>
              ))}
            </select>
            <select
              aria-label={t("common.outbound")}
              value={outbound}
              onChange={(event) => {
                setOutbound(event.target.value);
                changeFilter();
              }}
            >
              <option value="">
                {t("common.outbound")}: {t("common.all")}
              </option>
              {[
                "direct",
                "reject",
                ...(context.document?.config.outbounds.map((item) => item.name) ?? []),
              ].map((value) => (
                <option key={value} value={value}>
                  {["direct", "reject"].includes(value) ? t(`outbounds.${value}`) : value}
                </option>
              ))}
            </select>
          </>
        )}
        {search.view === "overview" && (
          <select
            aria-label={t("traffic.metric")}
            value={metric}
            onChange={(event) => {
              setMetric(event.target.value);
              changeFilter();
            }}
          >
            <option value="total">{t("common.total")}</option>
            <option value="upload">{t("common.upload")}</option>
            <option value="download">{t("common.download")}</option>
            <option value="cumulative">{t("traffic.bytes")}</option>
          </select>
        )}
        {search.view !== "dns" && (
          <details className="filterDetails">
            <summary>{t("common.filters")}</summary>
            <div className="toolbar">
              <select
                aria-label={t("traffic.rule")}
                value={rule}
                onChange={(event) => {
                  setRule(event.target.value);
                  changeFilter();
                }}
              >
                <option value="">
                  {t("traffic.rule")}: {t("common.all")}
                </option>
                {context.document?.config.rules.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.type} {item.pattern} → {item.outbound}
                  </option>
                ))}
              </select>
              <label>
                {t("logs.from")}
                <input
                  type="datetime-local"
                  value={since}
                  onChange={(event) => {
                    setSince(event.target.value);
                    changeFilter();
                  }}
                />
              </label>
              <label>
                {t("logs.to")}
                <input
                  type="datetime-local"
                  value={until}
                  onChange={(event) => {
                    setUntil(event.target.value);
                    changeFilter();
                  }}
                />
              </label>
            </div>
          </details>
        )}
        {(target || protocol || status || outbound || rule || since || until || search.anchor) && (
          <Button
            tone="quiet"
            onClick={() => {
              setTarget("");
              setProtocol("");
              setStatus("");
              setOutbound("");
              setRule("");
              setSince("");
              setUntil("");
              live();
            }}
          >
            {t("common.resetFilters")}
          </Button>
        )}
      </div>
      {search.view === "dns" ? (
        <DNSView target={filterTarget} />
      ) : (
        <>
          <ErrorNotice
            error={result.error}
            retry={() => {
              void result.refetch();
            }}
          />
          {data?.traffic.anchor_expired && (
            <div className="toolbar dangerText">
              {t("traffic.expired")}
              <Button onClick={live}>{t("common.resume")}</Button>
            </div>
          )}
          <div className="splitView">
            <div className="primaryPane">
              {!data ? (
                <div className="loading">{t("common.loading")}</div>
              ) : search.view === "overview" ? (
                <Overview data={data} onPath={drill} onFlow={setSelected} onGroup={drillGroup} />
              ) : (
                <Connections
                  key={JSON.stringify(filter)}
                  data={data}
                  onFreeze={() => setFrozen(data)}
                  filter={filter}
                  onSelect={setSelected}
                  selected={selected?.id}
                />
              )}
            </div>
            {selected && <FlowInspector flow={selected} onClose={() => setSelected(null)} />}
          </div>
        </>
      )}
    </section>
  );
}
function Overview({
  data,
  onPath,
  onFlow,
  onGroup,
}: {
  data: TrafficResponse;
  onPath: (paths: SankeyPath[]) => void;
  onFlow: (flow: Flow) => void;
  onGroup: (flows: Flow[]) => void;
}) {
  const { t } = useTranslation();
  const totals = data.traffic.totals;
  const attention = groupFlows(
    data.traffic.records.filter((flow) => ["failed", "rejected"].includes(flow.status)),
  );
  return (
    <>
      <div className={styles.telemetry}>
        <div>
          <span>{t("common.upload")}</span>
          <strong>{formatBytes(totals.upload_rate, true)}</strong>
        </div>
        <div>
          <span>{t("common.download")}</span>
          <strong>{formatBytes(totals.download_rate, true)}</strong>
        </div>
        <div>
          <span>{t("traffic.active")}</span>
          <strong>{formatNumber(totals.active)}</strong>
        </div>
        <div>
          <span>{t("traffic.failed")}</span>
          <strong className={totals.failed + totals.rejected > 0 ? "dangerText" : undefined}>
            {formatNumber(totals.failed + totals.rejected)}
          </strong>
        </div>
        <div>
          <span>{t("traffic.bytes")}</span>
          <strong>{formatBytes(totals.bytes)}</strong>
        </div>
      </div>
      {data.sankey.paths.length ? (
        <FlowGraph
          graph={data.sankey}
          onSelect={(pathIDs) => {
            onPath(data.sankey.paths.filter((item) => pathIDs.includes(item.id)));
          }}
        />
      ) : (
        <Empty title={t("common.noData")} description={t("traffic.pathEmpty")} />
      )}
      <div className="tableFoot">
        <span>
          {t("traffic.window")}: {timestamp(data.sankey.timestamp)}
        </span>
        <span>
          {t("traffic.session")}: <code>{data.traffic.session_id || "—"}</code>
        </span>
        {data.traffic.truncated && <span>{t("common.truncated")}</span>}
      </div>
      <section className={styles.attention}>
        <h2>
          {t("traffic.attention")} <span className="pill">{attention.length}</span>
        </h2>
        {attention.length ? (
          attention.slice(0, 8).map((group) => (
            <div key={group.key}>
              <button className="textButton mono" onClick={() => onGroup(group.flows)}>
                {group.target}
              </button>
              <span className="dangerText mono">{group.failed}</span>
              <span className="muted">
                {t(`stage.${group.flows[0].stage}`, { defaultValue: t("common.unknown") })} ·{" "}
                {timestamp(group.flows[0].updated_at)}
              </span>
              <Button tone="quiet" onClick={() => onFlow(group.flows[0])}>
                {t("common.openDetails")}
              </Button>
            </div>
          ))
        ) : (
          <p className="muted">{t("traffic.noAttention")}</p>
        )}
      </section>
      <details className={styles.paths}>
        <summary>{t("common.path")}</summary>
        <table className="dataTable">
          <thead>
            <tr>
              <th>{t("traffic.inbound")}</th>
              <th>{t("traffic.rule")}</th>
              <th>{t("traffic.actual")}</th>
              <th>{t("common.target")}</th>
              <th>{t("common.total")}</th>
            </tr>
          </thead>
          <tbody>
            {data.sankey.paths.map((path) => (
              <tr key={path.id}>
                <td>{path.inbound}</td>
                <td>{path.rule_name}</td>
                <td>
                  <OutboundName name={path.effective_outbound} />
                </td>
                <td>
                  <button className="textButton mono" onClick={() => onPath([path])}>
                    {path.other ? t("traffic.other") : path.target}
                  </button>
                </td>
                <td className="numeric">
                  {formatBytes(path.value, data.sankey.metric !== "cumulative")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </>
  );
}
function Connections({
  data,
  filter,
  onSelect,
  selected,
  onFreeze,
}: {
  data: TrafficResponse;
  filter: TrafficFilter;
  onSelect: (flow: Flow) => void;
  selected?: string;
  onFreeze: () => void;
}) {
  const { t } = useTranslation();
  const [grouped, setGrouped] = useWorkspaceState("connections.grouped", false);
  const [expanded, setExpanded] = useWorkspaceState<Set<string>>("connections.expanded", new Set());
  const [paging, setPaging] = useWorkspaceState("connections.paging", { anchor: "", page: 0 });
  const page = paging.anchor === data.traffic.anchor ? paging.page : 0;
  function setPage(value: number) {
    onFreeze();
    setPaging({ anchor: data.traffic.anchor, page: value });
  }
  const [extra, setExtra] = useWorkspaceState<{
    anchor: string;
    flows: Flow[];
    cursor?: string;
  } | null>("connections.extra", null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const records =
    extra?.anchor === data.traffic.anchor
      ? [...data.traffic.records, ...extra.flows]
      : data.traffic.records;
  const groups = groupFlows(records);
  const count = grouped ? groups.length : records.length;
  const cursor = extra?.anchor === data.traffic.anchor ? extra.cursor : data.traffic.next_cursor;
  async function more() {
    onFreeze();
    setBusy(true);
    setError(null);
    try {
      const result = await api.flows({
        ...filter,
        anchor: data.traffic.anchor,
        cursor,
        limit: "200",
      });
      setExtra((previous) => ({
        anchor: data.traffic.anchor,
        flows: [
          ...(previous?.anchor === data.traffic.anchor ? previous.flows : []),
          ...result.records,
        ],
        cursor: result.next_cursor,
      }));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="toolbar">
        <Toggle
          checked={grouped}
          onChange={(value) => {
            setGrouped(value);
            setPage(0);
          }}
          label={t("traffic.group")}
        />
        <span className="spacer" />
        <small className="muted">{t("traffic.loadedOnly")}</small>
      </div>
      <ErrorNotice error={error} />
      <table className="dataTable">
        <thead>
          <tr>
            <th>{t("common.target")}</th>
            <th>{t("common.protocol")}</th>
            <th>{t("traffic.rule")}</th>
            <th>{t("traffic.actual")}</th>
            <th>{t("common.status")}</th>
            <th className="numeric">↑ / ↓</th>
            <th>{t("common.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {grouped
            ? groups.slice(page * 50, (page + 1) * 50).map((group) => (
                <Fragment key={group.key}>
                  <tr className={styles.group}>
                    <td>
                      <button
                        className="textButton mono"
                        aria-expanded={expanded.has(group.key)}
                        onClick={() =>
                          setExpanded((previous) => {
                            onFreeze();
                            return previous.has(group.key)
                              ? new Set<string>()
                              : new Set([group.key]);
                          })
                        }
                      >
                        {expanded.has(group.key) ? "−" : "+"} {group.target}
                      </button>
                    </td>
                    <td colSpan={3}>
                      {group.flows.length} {t("common.connections")}
                    </td>
                    <td>
                      {group.active} {t("traffic.active")} / {group.failed} {t("traffic.failed")}
                    </td>
                    <td className="numeric">
                      {formatBytes(group.upload)} / {formatBytes(group.download)}
                    </td>
                    <td aria-label={t("common.actions")} />
                  </tr>
                  {expanded.has(group.key) &&
                    group.flows
                      .slice(0, 50)
                      .map((flow) => (
                        <FlowRow
                          key={flow.id}
                          flow={flow}
                          onSelect={onSelect}
                          selected={selected === flow.id}
                        />
                      ))}
                  {expanded.has(group.key) && group.flows.length > 50 && (
                    <tr>
                      <td colSpan={7}>
                        <span className="muted">
                          {t("traffic.groupLimit", { count: group.flows.length })}
                        </span>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))
            : records
                .slice(page * 50, (page + 1) * 50)
                .map((flow) => (
                  <FlowRow
                    key={flow.id}
                    flow={flow}
                    onSelect={onSelect}
                    selected={selected === flow.id}
                  />
                ))}
        </tbody>
      </table>
      {!records.length && <Empty title={t("common.empty")} description={t("common.noMatches")} />}
      <div className="tableFoot">
        <span>
          {formatNumber(count)} {t(grouped ? "common.target" : "common.connections")}
        </span>
        <Button disabled={page === 0} onClick={() => setPage(page - 1)}>
          {t("common.previous")}
        </Button>
        <span>
          {page + 1} / {Math.max(1, Math.ceil(count / 50))}
        </span>
        <Button disabled={(page + 1) * 50 >= count} onClick={() => setPage(page + 1)}>
          {t("common.next")}
        </Button>
        {cursor && (
          <Button
            onClick={() => {
              void more();
            }}
            disabled={busy}
          >
            {t("traffic.loadMore")}
          </Button>
        )}
        {data.traffic.truncated && <span>{t("common.truncated")}</span>}
      </div>
    </>
  );
}
function FlowRow({
  flow,
  onSelect,
  selected,
}: {
  flow: Flow;
  onSelect: (flow: Flow) => void;
  selected: boolean;
}) {
  const actions = useTargetActions(flowTarget(flow), flow.protocol);
  return (
    <ContextActions actions={actions}>
      <tr data-selected={selected}>
        <td className="targetCell mono">
          <button className="textButton" onClick={() => onSelect(flow)}>
            {flow.domain || flow.target || flow.destination}
          </button>
        </td>
        <td className="mono muted">{flow.protocol.toUpperCase()}</td>
        <td>{flow.rule_name || "—"}</td>
        <td>
          <OutboundName name={flow.effective_outbound} />
        </td>
        <td>
          <Status value={flow.status} />
        </td>
        <td className="numeric nowrap">
          {formatBytes(flow.upload)} / {formatBytes(flow.download)}
        </td>
        <td>
          <ActionMenu actions={actions} />
        </td>
      </tr>
    </ContextActions>
  );
}
function FlowInspector({ flow, onClose }: { flow: Flow; onClose: () => void }) {
  const { t } = useTranslation();
  const actions = useTargetActions(flowTarget(flow), flow.protocol);
  const context = useConsole();
  const search = useSearch({ from: "/traffic" });
  const matchedRule = context.document?.config.rules.find((rule) => rule.id === flow.rule_id);
  return (
    <aside className="inspector" aria-label={t("common.openDetails")}>
      <header>
        <h2>{flow.domain || flow.target || flow.destination}</h2>
        <Button tone="quiet" onClick={onClose} aria-label={t("common.close")}>
          ×
        </Button>
      </header>
      <Status value={flow.status} />
      <div className="actions">
        <ActionMenu actions={actions}>{t("traffic.createRule")}</ActionMenu>
        <Button
          disabled={actions.find((action) => action.id === "diagnose")!.disabled}
          onClick={actions.find((action) => action.id === "diagnose")!.run}
        >
          {t("traffic.diagnose")}
        </Button>
        {flow.domain && (
          <Link to="/traffic" search={{ ...search, view: "dns", target: flow.domain }}>
            {t("nav.dns")}
          </Link>
        )}
        {matchedRule &&
          (matchedRule.type !== "FINAL" ||
            !context.document?.config.policy?.mode ||
            context.document.config.policy.mode === "custom") && (
            <Button disabled={!context.admin} onClick={() => context.setRuleDraft(matchedRule)}>
              {t("rules.editCurrent")}
            </Button>
          )}
      </div>
      <KeyValues
        entries={[
          [t("traffic.source"), flow.source],
          [t("traffic.destination"), flow.destination],
          [t("common.source"), flow.domain_source || t("common.unknown")],
          [t("diagnostics.stage"), t(`stage.${flow.stage}`, { defaultValue: t("common.unknown") })],
          [t("traffic.realIP"), flow.real_destination || t("common.unknown")],
          [t("traffic.fakeIP"), flow.fake_ip || "—"],
          [t("traffic.process"), flow.process_name || t("common.unknown")],
          [t("traffic.rule"), flow.rule_name],
          [
            t("traffic.rulePool"),
            flow.decision_pool ? t(`policy.pool.${flow.decision_pool}`) : t("policy.legacyOrder"),
          ],
          [
            t("traffic.ruleEvidence"),
            flow.decision_evidence ? t(`policy.evidence.${flow.decision_evidence}`) : "—",
          ],
          [t("traffic.authorizedTargets"), flow.authorized_candidates?.join(", ") || "—"],
          [t("traffic.expected"), <OutboundName key="expected" name={flow.expected_outbound} />],
          [t("traffic.actual"), <OutboundName key="actual" name={flow.effective_outbound} />],
          [t("common.version"), `v${flow.config_version}`],
          [t("common.upload"), formatBytes(flow.upload)],
          [t("common.download"), formatBytes(flow.download)],
          [t("traffic.started"), timestamp(flow.started_at)],
          [t("traffic.ended"), timestamp(flow.ended_at)],
        ]}
      />
      <Details value={flow} />
    </aside>
  );
}
function DNSView({ target }: { target: string }) {
  const { t } = useTranslation();
  const [type, setType] = useWorkspaceState("dns.type", "");
  const [selected, setSelected] = useWorkspaceState<DNSQuery | null>("dns.selected", null);
  const [frozen, setFrozen] = useWorkspaceState<DNSQuery[] | null>("dns.frozen", null);
  const [page, setPage] = useWorkspaceState("dns.page", 0);
  const data = useQuery({
    queryKey: ["dns"],
    queryFn: ({ signal }) => api.dns(signal),
    refetchInterval: frozen ? false : 1500,
  });
  const rows = (frozen ?? data.data?.queries ?? []).filter(
    (event) =>
      event.name.toLowerCase().includes(target.toLowerCase()) && (!type || event.type === type),
  );
  const currentPage = Math.min(page, Math.max(0, Math.ceil(rows.length / 50) - 1));
  function movePage(next: number) {
    if (!frozen) setFrozen(data.data?.queries ?? []);
    setPage(next);
  }
  return (
    <>
      <div className="toolbar">
        <select
          aria-label={t("dns.type")}
          value={type}
          onChange={(event) => {
            setType(event.target.value);
            setPage(0);
          }}
        >
          <option value="">
            {t("dns.type")}: {t("common.all")}
          </option>
          {["A", "AAAA", "HTTPS", "CNAME", "PTR"].map((value) => (
            <option key={value}>{value}</option>
          ))}
        </select>
        <Button onClick={() => setFrozen(frozen ? null : (data.data?.queries ?? []))}>
          {t(frozen ? "common.resume" : "common.freeze")}
        </Button>
        <span className="spacer" />
        <Link to="/settings" search={{ section: "resolvers" }}>
          {t("dns.configure")}
        </Link>
      </div>
      <ErrorNotice error={data.error} />
      <div className="splitView">
        <div className="primaryPane">
          <table className="dataTable">
            <thead>
              <tr>
                {[
                  "common.time",
                  "dns.query",
                  "dns.type",
                  "dns.resolver",
                  "dns.latency",
                  "dns.cache",
                  "common.status",
                  "common.actions",
                ].map((key) => (
                  <th key={key}>{t(key)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.slice(currentPage * 50, (currentPage + 1) * 50).map((event) => (
                <DNSRow key={event.id} event={event} onSelect={() => setSelected(event)} />
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty title={t("common.empty")} description={t("dns.noQueries")} />}
          <div className="tableFoot">
            <span>
              {formatNumber(rows.length)} {t("dns.query")}
            </span>
            <Button disabled={currentPage === 0} onClick={() => movePage(currentPage - 1)}>
              {t("common.previous")}
            </Button>
            <span className="mono">
              {currentPage + 1} / {Math.max(1, Math.ceil(rows.length / 50))}
            </span>
            <Button
              disabled={(currentPage + 1) * 50 >= rows.length}
              onClick={() => movePage(currentPage + 1)}
            >
              {t("common.next")}
            </Button>
          </div>
          <div className="surface">
            <Details value={data.data?.status} />
          </div>
        </div>
        {selected && <DNSInspector event={selected} onClose={() => setSelected(null)} />}
      </div>
    </>
  );
}
function DNSRow({ event, onSelect }: { event: DNSQuery; onSelect: () => void }) {
  const actions = useTargetActions(event.name);
  const { t } = useTranslation();
  return (
    <ContextActions actions={actions}>
      <tr>
        <td className="muted nowrap">{timestamp(event.time)}</td>
        <td className="mono">
          <button className="textButton" onClick={onSelect}>
            {event.name}
          </button>
        </td>
        <td className="mono">{event.type}</td>
        <td className="mono muted">{event.upstream || "—"}</td>
        <td className="numeric">{formatNumber(event.duration_ms, 2)} ms</td>
        <td>{t(`dns.cache.${event.cache}`, { defaultValue: t("common.unknown") })}</td>
        <td>
          <Status value={event.status} />
        </td>
        <td>
          <ActionMenu actions={actions} />
        </td>
      </tr>
    </ContextActions>
  );
}
function DNSInspector({ event, onClose }: { event: DNSQuery; onClose: () => void }) {
  const { t } = useTranslation();
  const actions = useTargetActions(event.name);
  return (
    <aside className="inspector">
      <header>
        <h2>{event.name}</h2>
        <Button tone="quiet" onClick={onClose} aria-label={t("common.close")}>
          ×
        </Button>
      </header>
      <p className="inlineNote">{t("dns.ruleHint")}</p>
      <ActionMenu actions={actions}>{t("traffic.createRule")}</ActionMenu>
      <KeyValues
        entries={[
          [t("dns.type"), event.type],
          [t("dns.resolver"), event.upstream || "—"],
          [t("settings.interface"), event.resolver_interface || "—"],
          [t("traffic.realIP"), event.real_addresses?.join(", ") || "—"],
          [t("traffic.fakeIP"), event.virtual_addresses?.join(", ") || "—"],
          [t("common.version"), event.version],
          [t("common.time"), timestamp(event.time)],
        ]}
      />
      <Details value={event} />
    </aside>
  );
}
