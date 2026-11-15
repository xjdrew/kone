import type { Sankey } from "./model";
export function graphLayout(graph: Sankey) {
  const width = 1080,
    gap = 12,
    top = 46;
  const columns = [0, 1, 2, 3].map((column) =>
    graph.nodes.filter((node) => node.column === column),
  );
  const maxCount = Math.max(1, ...columns.map((nodes) => nodes.length));
  const height = Math.min(360, Math.max(72, maxCount * 35));
  const weights = new Map(
    graph.nodes.map((node) => [
      node.id,
      Math.max(
        graph.links
          .filter((link) => link.source === node.id)
          .reduce((sum, link) => sum + link.value, 0),
        graph.links
          .filter((link) => link.target === node.id)
          .reduce((sum, link) => sum + link.value, 0),
      ),
    ]),
  );
  const maxTotal = Math.max(
    1,
    ...columns.map((nodes) => nodes.reduce((sum, node) => sum + (weights.get(node.id) || 0), 0)),
  );
  const scale = Math.max(40, height - Math.max(0, maxCount - 1) * gap) / maxTotal;
  const nodes = columns.flatMap((column, index) => {
    let y = top;
    return column.map((node) => {
      const weight = weights.get(node.id) || 0;
      const h = weight * scale;
      const result = { ...node, x: 24 + (index * (width - 48)) / 3, y, height: h, weight };
      y += Math.max(h, 2) + gap;
      return result;
    });
  });
  const lookup = new Map(nodes.map((node) => [node.id, node]));
  const sourceOffset = new Map<string, number>();
  const targetOffset = new Map<string, number>();
  const links = graph.links
    .filter((link) => link.value > 0)
    .flatMap((link) => {
      const source = lookup.get(link.source),
        target = lookup.get(link.target);
      if (!source || !target) return [];
      const h = link.value * scale;
      const sy = source.y + (sourceOffset.get(source.id) || 0),
        ty = target.y + (targetOffset.get(target.id) || 0);
      sourceOffset.set(source.id, (sourceOffset.get(source.id) || 0) + h);
      targetOffset.set(target.id, (targetOffset.get(target.id) || 0) + h);
      const sx = source.x + 5,
        tx = target.x - 5,
        mid = (sx + tx) / 2;
      return [
        {
          ...link,
          path: `M${sx},${sy} C${mid},${sy} ${mid},${ty} ${tx},${ty} L${tx},${ty + h} C${mid},${ty + h} ${mid},${sy + h} ${sx},${sy + h} Z`,
        },
      ];
    });
  return {
    nodes,
    links,
    width,
    height: Math.max(height + top + 30, ...nodes.map((node) => node.y + node.height + 28)),
  };
}
