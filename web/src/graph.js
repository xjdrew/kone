const svgNS = "http://www.w3.org/2000/svg";
export const palette = [
  "#73e0c1",
  "#80b8ff",
  "#c1a3ff",
  "#f6bd76",
  "#ed91b3",
  "#92c5cc",
];
export function colorFor(key) {
  let value = 0;
  for (const character of String(key))
    value = (value * 31 + character.charCodeAt(0)) >>> 0;
  return palette[value % palette.length];
}
export function bytes(value, rate = false) {
  value = Number(value) || 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i++;
  }
  return `${value.toLocaleString("zh-CN", { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}${rate ? "/s" : ""}`;
}
const keyOf = (values) => JSON.stringify(values);
export function aggregatePaths(
  flows,
  { metric = "cumulative", direction = "total", protocol = "", top = 8 } = {},
) {
  const relevant = flows.filter(
    (flow) =>
      (!flow.category || flow.category === "business") &&
      (!protocol || flow.protocol === protocol),
  );
  const weighted = relevant.map((flow) => {
    const upload = metric === "rate" ? flow.upload_rate : flow.upload;
    const download = metric === "rate" ? flow.download_rate : flow.download;
    return {
      flow,
      value: Math.max(
        0,
        direction === "upload"
          ? upload
          : direction === "download"
            ? download
            : upload + download,
      ),
    };
  });
  const totals = new Map();
  for (const { flow, value } of weighted)
    totals.set(flow.target, (totals.get(flow.target) || 0) + value);
  const visible = new Set(
    [...totals]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, top)
      .map(([target]) => target),
  );
  const topValues = (key) => {
    const values = new Map();
    for (const { flow, value } of weighted)
      values.set(flow[key], (values.get(flow[key]) || 0) + value);
    return new Set(
      [...values]
        .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
        .slice(0, Math.max(1, Math.min(20, top)))
        .map(([name]) => name),
    );
  };
  const inbounds = topValues("inbound");
  const rules = topValues("rule_id");
  const outbounds = topValues("outbound");
  const grouped = new Map();
  let total = 0;
  let failed = 0;
  for (const { flow, value } of weighted) {
    if (["failed", "rejected", "reject"].includes(flow.status)) failed++;
    if (!value) continue; // Never invent positive width for a zero-byte event.
    const target = visible.has(flow.target) ? flow.target : "其他目的";
    const nodes = [
      {
        id: inbounds.has(flow.inbound) ? `in:${flow.inbound}` : "in:other",
        label: inbounds.has(flow.inbound) ? flow.inbound : "其他入站",
        column: 0,
        type: "inbound",
      },
      {
        id: rules.has(flow.rule_id) ? `rule:${flow.rule_id}` : "rule:other",
        label: rules.has(flow.rule_id) ? flow.rule : "其他规则",
        column: 1,
        type: "rule",
      },
      {
        id: outbounds.has(flow.outbound) ? `out:${flow.outbound}` : "out:other",
        label: outbounds.has(flow.outbound) ? flow.outbound : "其他出站",
        column: 2,
        type: "outbound",
      },
      {
        id: `dest:${target}`,
        label: target,
        column: 3,
        type: target === "其他目的" ? "other" : "destination",
      },
    ];
    const key = keyOf(nodes.map((node) => node.id));
    if (!grouped.has(key))
      grouped.set(key, {
        key,
        nodes,
        value: 0,
        flow_ids: [],
        count: 0,
        destinations: new Set(),
      });
    const path = grouped.get(key);
    path.value += value;
    path.count++;
    path.flow_ids.push(flow.id);
    path.destinations.add(flow.target);
    total += value;
  }
  return {
    paths: [...grouped.values()].map((path) => ({
      ...path,
      destinations: [...path.destinations],
    })),
    total,
    failed,
    count: relevant.length,
    unit: metric === "rate" ? "B/s" : "B",
  };
}

// Native snapshots contain measured path rates and immutable query anchors.
// Never derive per-path speed from cumulative counters or independent totals.
export function nativePaths(
  snapshot,
  { metric = "rate", direction = "total" } = {},
) {
  if (!snapshot?.paths) return null;
  const versions = new Set(
    snapshot.paths.map((path) => path.config_version ?? "unknown"),
  );
  const paths = snapshot.paths
    .map((path) => {
      const version = path.config_version ?? "unknown";
      const versionLabel =
        versions.size > 1
          ? version === "unknown"
            ? " · 版本未知"
            : ` · v${version}`
          : "";
      const value =
        metric === "cumulative" && direction !== "total"
          ? Number(path[direction] || 0)
          : Number(path.value || 0);
      const nodes = [
        {
          id: `in:${path.inbound}`,
          label: path.inbound || "未知入口",
          column: 0,
          type: "inbound",
        },
        {
          id: `rule:${version}:${path.rule_id}`,
          color_key: `rule:${path.rule_id}`,
          label: `${path.rule_name || "默认策略"}${versionLabel}`,
          column: 1,
          type: "rule",
        },
        {
          id: `out:${version}:${path.effective_outbound}`,
          color_key: `out:${path.effective_outbound}`,
          label: `${path.effective_outbound || "未建立出站"}${versionLabel}`,
          column: 2,
          type: "outbound",
        },
        {
          id: `dest:${path.target}`,
          label: path.other ? "其他目的" : path.target || "未知目的",
          column: 3,
          type: path.other ? "other" : "destination",
        },
      ];
      return {
        key: path.id,
        nodes,
        value: Math.max(0, value),
        count: path.connections || 0,
        flow_ids: path.filter?.flow_ids || [],
        destinations: [path.target],
        filter: path.filter,
        native: true,
      };
    })
    .filter((path) => path.value > 0);
  return {
    paths,
    total: paths.reduce((sum, path) => sum + path.value, 0),
    failed: snapshot.failures || 0,
    count: paths.reduce((sum, path) => sum + path.count, 0),
    unit: snapshot.unit,
    anchor: snapshot.anchor,
    window_start: snapshot.window_start,
    window_end: snapshot.window_end,
    native: true,
  };
}

export function buildGraph(aggregation, width = 1000) {
  const columns = Array.from({ length: 4 }, () => []);
  const nodeMap = new Map();
  const edgeMap = new Map();
  for (const path of aggregation.paths) {
    for (const node of path.nodes) {
      if (!nodeMap.has(node.id)) {
        const fresh = {
          ...node,
          value: 0,
          paths: [],
          inOffset: 0,
          outOffset: 0,
        };
        nodeMap.set(node.id, fresh);
        columns[node.column].push(fresh);
      }
      const fresh = nodeMap.get(node.id);
      fresh.value += path.value;
      fresh.paths.push(path.key);
    }
    for (let i = 0; i < path.nodes.length - 1; i++) {
      const source = path.nodes[i].id;
      const target = path.nodes[i + 1].id;
      const key = keyOf([source, target]);
      if (!edgeMap.has(key))
        edgeMap.set(key, {
          id: key,
          source,
          target,
          value: 0,
          paths: [],
          flow_ids: new Set(),
        });
      const edge = edgeMap.get(key);
      edge.value += path.value;
      edge.paths.push(path.key);
      path.flow_ids.forEach((id) => edge.flow_ids.add(id));
    }
  }
  const count = Math.max(2, ...columns.map((column) => column.length));
  const height = Math.max(300, Math.min(720, count * 60 + 60));
  const padding = 20;
  const available = height - 72 - (count - 1) * padding;
  const scale = aggregation.total ? available / aggregation.total : 0;
  for (let columnIndex = 0; columnIndex < columns.length; columnIndex++) {
    const column = columns[columnIndex];
    column.sort((a, b) => a.id.localeCompare(b.id));
    const used =
      column.reduce((value, node) => value + node.value * scale, 0) +
      (column.length - 1) * padding;
    let y = 42 + (height - 72 - used) / 2;
    for (const node of column) {
      node.x = 26 + (columnIndex * (width - 66)) / 3;
      node.y = y;
      node.height = node.value * scale;
      node.color = colorFor(node.color_key || node.id);
      y += node.height + padding;
    }
  }
  const edges = [...edgeMap.values()].sort(
    (a, b) =>
      a.source.localeCompare(b.source) || a.target.localeCompare(b.target),
  );
  for (const edge of edges) {
    const source = nodeMap.get(edge.source);
    const target = nodeMap.get(edge.target);
    const thickness = edge.value * scale;
    const y0 = source.y + source.outOffset;
    const y1 = target.y + target.inOffset;
    source.outOffset += thickness;
    target.inOffset += thickness;
    const x0 = source.x + 10;
    const x1 = target.x;
    const dx = (x1 - x0) * 0.48;
    edge.d = `M${x0},${y0} C${x0 + dx},${y0} ${x1 - dx},${y1} ${x1},${y1} L${x1},${y1 + thickness} C${x1 - dx},${y1 + thickness} ${x0 + dx},${y0 + thickness} ${x0},${y0 + thickness} Z`;
    edge.flow_ids = [...edge.flow_ids];
    const colorNode = edge.target.startsWith("out:") ? target : source;
    edge.color = colorFor(colorNode.color_key || colorNode.id);
  }
  return {
    nodes: [...nodeMap.values()],
    edges,
    columns,
    width,
    height,
    total: aggregation.total,
  };
}

function svg(name, attributes = {}, text) {
  const element = document.createElementNS(svgNS, name);
  for (const [key, value] of Object.entries(attributes))
    element.setAttribute(key, value);
  if (text !== undefined) element.textContent = text;
  return element;
}

export function renderSankey(
  container,
  aggregation,
  { onSelect, selected = null, metric = "cumulative" } = {},
) {
  container.replaceChildren();
  if (!aggregation.paths.length) {
    const empty = document.createElement("div");
    empty.className = "graph-empty";
    const symbol = document.createElement("span");
    symbol.className = "empty-symbol";
    symbol.textContent = "↝";
    const title = document.createElement("h3");
    title.textContent = "尚无可绘制的业务流量";
    const text = document.createElement("p");
    text.textContent = aggregation.failed
      ? `有 ${aggregation.failed} 条失败或拒绝事件，零字节事件不会绘成流量。`
      : "流量进入 KONE 后，实际路径会显示在这里。未进入 KONE 的连接不可观察。";
    empty.append(symbol, title, text);
    container.append(empty);
    return;
  }
  const graph = buildGraph(aggregation);
  const canvas = svg("svg", {
    viewBox: `0 0 ${graph.width} ${graph.height}`,
    role: "img",
    "aria-label": "业务流量桑基图：入站、规则、实际出站、最终目的",
  });
  canvas.append(
    svg("title", {}, "KONE 实际业务路径。可使用键盘或点选路径查看连接。"),
  );
  const labels = ["入站", "规则 / 策略", "实际出站", "最终业务目的"];
  labels.forEach((label, index) =>
    canvas.append(
      svg(
        "text",
        {
          x: 26 + (index * (graph.width - 66)) / 3,
          y: 18,
          class: "graph-column",
          "text-anchor": index === 3 ? "end" : "start",
        },
        label,
      ),
    ),
  );
  const focusPaths = selected?.paths || null;
  for (const edge of graph.edges) {
    const shape = svg("path", {
      d: edge.d,
      fill: edge.color,
      class: "sankey-edge",
      tabindex: 0,
      role: "button",
      "aria-label": `${graph.nodes.find((node) => node.id === edge.source).label} 到 ${graph.nodes.find((node) => node.id === edge.target).label}，${bytes(edge.value, metric === "rate")}`,
    });
    if (focusPaths && !edge.paths.some((path) => focusPaths.includes(path)))
      shape.classList.add("dimmed");
    shape.append(
      svg(
        "title",
        {},
        `${bytes(edge.value, metric === "rate")} · ${edge.flow_ids.length} 条连接`,
      ),
    );
    const select = () =>
      onSelect?.({
        label: `${graph.nodes.find((node) => node.id === edge.source).label} → ${graph.nodes.find((node) => node.id === edge.target).label}`,
        paths: edge.paths,
        flow_ids: edge.flow_ids,
        count: aggregation.paths
          .filter((path) => edge.paths.includes(path.key))
          .reduce((sum, path) => sum + path.count, 0),
        value: edge.value,
        anchor: aggregation.anchor,
      });
    shape.addEventListener("click", select);
    shape.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        select();
      }
    });
    canvas.append(shape);
  }
  for (const node of graph.nodes) {
    const group = svg("g", {
      class: "sankey-node",
      tabindex: 0,
      role: "button",
      "aria-label": `${node.label}，${bytes(node.value, metric === "rate")}`,
    });
    group.append(
      svg("rect", {
        x: node.x,
        y: node.y,
        width: 10,
        height: Math.max(0.05, node.height),
        rx: 3,
        fill: node.color,
      }),
    );
    const labelX = node.column === 3 ? node.x - 10 : node.x + 20;
    const label =
      node.label.length > 20 ? `${node.label.slice(0, 18)}…` : node.label;
    group.append(
      svg(
        "text",
        {
          x: labelX,
          y: node.y + node.height / 2 + 4,
          "text-anchor": node.column === 3 ? "end" : "start",
          class: "graph-label",
        },
        label,
      ),
    );
    group.append(svg("title", {}, node.label));
    if (focusPaths && !node.paths.some((path) => focusPaths.includes(path)))
      group.classList.add("dimmed");
    const select = () => {
      const paths = aggregation.paths.filter((path) =>
        node.paths.includes(path.key),
      );
      onSelect?.({
        label: node.label,
        paths: node.paths,
        flow_ids: [...new Set(paths.flatMap((path) => path.flow_ids))],
        count: paths.reduce((sum, path) => sum + path.count, 0),
        value: node.value,
        anchor: aggregation.anchor,
      });
    };
    group.addEventListener("click", select);
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        select();
      }
    });
    canvas.append(group);
  }
  container.append(canvas);
}
