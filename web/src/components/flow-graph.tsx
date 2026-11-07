import { graphLayout } from "../graph-layout";
/* SVG interactive paths require ARIA roles; HTML buttons cannot replace them. */
/* oxlint-disable jsx-a11y/prefer-tag-over-role */
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { formatBytes } from "../domain";
import type { Sankey } from "../model";
import styles from "./flow-graph.module.css";

const colors = ["#73e0c1", "#82b6ed", "#b2a6ed", "#dbb577", "#d890a4"];
function color(id: string) {
  let hash = 0;
  for (const char of id) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return colors[hash % colors.length];
}
export function FlowGraph({
  graph,
  onSelect,
}: {
  graph: Sankey;
  onSelect: (paths: string[]) => void;
}) {
  const { t } = useTranslation();
  const layout = useMemo(() => graphLayout(graph), [graph]);
  const [pinned, setPinned] = useState<string[]>([]);
  function select(paths: string[]) {
    if (window.matchMedia("(pointer: coarse)").matches) setPinned(paths);
    else onSelect(paths);
  }
  function activate(event: React.KeyboardEvent, paths: string[]) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(paths);
    }
  }
  return (
    <div className={styles.graph}>
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        role="group"
        aria-label={t("traffic.title")}
      >
        {["traffic.inbound", "traffic.rule", "traffic.actual", "traffic.destination"].map(
          (key, index) => (
            <text
              key={key}
              x={24 + (index * (layout.width - 48)) / 3}
              y="22"
              textAnchor={index === 3 ? "end" : "start"}
              className={styles.heading}
            >
              {t(key)}
            </text>
          ),
        )}
        {layout.links.map((link) => (
          <path
            key={link.id}
            d={link.path}
            fill={color(link.source)}
            className={styles.link}
            role="button"
            tabIndex={0}
            aria-label={`${t("common.path")}: ${formatBytes(link.value, graph.metric !== "cumulative")}`}
            onClick={() => select(link.path_ids)}
            aria-pressed={pinned.length > 0 && link.path_ids.some((id) => pinned.includes(id))}
            onKeyDown={(event) => activate(event, link.path_ids)}
          >
            <title>{formatBytes(link.value, graph.metric !== "cumulative")}</title>
          </path>
        ))}
        {layout.nodes.map((node) => {
          const paths = [
            ...new Set(
              graph.links
                .filter((link) => link.source === node.id || link.target === node.id)
                .flatMap((link) => link.path_ids),
            ),
          ];
          const label = ["direct", "reject"].includes(node.label)
            ? t(`outbounds.${node.label}`)
            : node.label;
          return (
            <g
              key={node.id}
              role="button"
              tabIndex={0}
              aria-label={`${label}: ${formatBytes(node.weight, graph.metric !== "cumulative")}`}
              onClick={() => select(paths)}
              onKeyDown={(event) => activate(event, paths)}
              className={styles.node}
            >
              <rect
                x={node.column === 3 ? node.x - 220 : node.x - 4}
                y={node.y}
                width="224"
                height={Math.max(20, node.height)}
                fill="transparent"
              />
              <rect
                x={node.x - 4}
                y={node.y}
                width="8"
                height={Math.max(2, node.height)}
                fill={color(node.id)}
              />
              <text
                x={node.column === 3 ? node.x - 12 : node.x + 12}
                y={node.y + Math.min(14, node.height / 2 + 4)}
                textAnchor={node.column === 3 ? "end" : "start"}
              >
                {label.length > 29 ? `${label.slice(0, 27)}…` : label}
              </text>
              <title>{label}</title>
            </g>
          );
        })}
      </svg>
      {pinned.length > 0 && (
        <div className="toolbar">
          <span className="mono">
            {graph.paths
              .filter((path) => pinned.includes(path.id))
              .map((path) => path.target)
              .slice(0, 3)
              .join(", ")}
          </span>
          <button onClick={() => onSelect(pinned)}>{t("traffic.inspectSelection")}</button>
          <button onClick={() => setPinned([])}>{t("common.cancel")}</button>
        </div>
      )}
    </div>
  );
}
