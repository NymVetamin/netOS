type Point = { at: number; value: number | null; gap?: number };

// Build both paths in one pass. Each continuous segment closes at the baseline;
// missing measurements must stay empty rather than become interpolated areas.
export function chartPaths(points: Point[], x: (at: number) => number, y: (value: number) => number, baseline: number, digits: number) {
 const stroke: string[] = [], area: string[] = [];
 let previous: Point | null = null, firstX = "", lastX = "";
 const close = () => { if (previous) area.push(`L${lastX},${baseline} L${firstX},${baseline} Z`); };
 for (const point of points) {
  if (point.value == null) { close(); previous = null; continue; }
  const connected = previous != null && point.at - previous.at <= Math.max(point.gap || 3, previous.gap || 3);
  const px = x(point.at).toFixed(digits), py = y(point.value).toFixed(digits);
  if (!connected) { close(); firstX = px; }
  const command = `${connected ? "L" : "M"}${px},${py}`;
  stroke.push(command); area.push(command); lastX = px; previous = point;
 }
 close();
 return { stroke: stroke.join(" "), area: area.join(" ") };
}
