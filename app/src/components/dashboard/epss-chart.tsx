import { type DashboardEpssTrend as EpssTrend } from "@/lib/queries";
import { SectionHeader } from "@/components/dashboard/section-header";

const CHART_COLORS = [
  "var(--severity-critical)",
  "var(--severity-high)",
  "var(--status-info)",
];

function buildPath(
  trends: EpssTrend[],
  cveId: string,
  width: number,
  height: number,
  padding: number,
): string {
  const values = trends.map((t) => t.scores[cveId]);
  const min = Math.min(...values) - 0.05;
  const max = Math.max(...values) + 0.05;
  const xStep = (width - padding * 2) / (values.length - 1);

  return values
    .map((v, i) => {
      const x = padding + i * xStep;
      const y =
        height -
        padding -
        ((v - min) / (max - min)) * (height - padding * 2);
      return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
}

function buildAreaPath(
  trends: EpssTrend[],
  cveId: string,
  width: number,
  height: number,
  padding: number,
): string {
  const linePath = buildPath(trends, cveId, width, height, padding);
  const xStart = padding;
  const xEnd =
    padding +
    ((trends.length - 1) * (width - padding * 2)) / (trends.length - 1);
  return `${linePath} L ${xEnd.toFixed(1)} ${height - padding} L ${xStart.toFixed(1)} ${height - padding} Z`;
}

/* We use inline hex fallbacks for SVG gradient stops since CSS vars
   don't work reliably in SVG stop-color across all browsers. These
   fallbacks match the CSS variable values defined in globals.css. */
const GRADIENT_FALLBACKS = ["#f85149", "#f0883e", "#58a6ff"];

export function EpssChart({ trends }: { trends: EpssTrend[] }) {
  const width = 400;
  const height = 220;
  const padding = 30;
  const cveIds = Object.keys(trends[0].scores);

  return (
    <div className="space-y-4">
      <SectionHeader title="EPSS Trends" />
      <div className="rounded-lg border border-border bg-card p-4">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-auto"
          role="img"
          aria-label="EPSS score trends over time"
        >
          <defs>
            {cveIds.map((_, idx) => (
              <linearGradient
                key={idx}
                id={`grad-${idx}`}
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="0%"
                  stopColor={GRADIENT_FALLBACKS[idx % GRADIENT_FALLBACKS.length]}
                  stopOpacity="0.15"
                />
                <stop
                  offset="100%"
                  stopColor={GRADIENT_FALLBACKS[idx % GRADIENT_FALLBACKS.length]}
                  stopOpacity="0"
                />
              </linearGradient>
            ))}
          </defs>

          {/* Grid lines */}
          {[0.25, 0.5, 0.75].map((frac) => {
            const y = padding + frac * (height - padding * 2);
            return (
              <line
                key={frac}
                x1={padding}
                y1={y}
                x2={width - padding}
                y2={y}
                className="stroke-border"
                strokeWidth={0.5}
                strokeDasharray="3 3"
              />
            );
          })}

          {/* X-axis labels */}
          {trends.map((t, i) => {
            const x =
              padding + (i * (width - padding * 2)) / (trends.length - 1);
            return (
              <text
                key={t.date}
                x={x}
                y={height - 8}
                textAnchor="middle"
                className="fill-muted-foreground/60"
                fontSize={10}
                fontFamily="inherit"
              >
                {t.date}
              </text>
            );
          })}

          {/* Area fills */}
          {cveIds.map((cveId, idx) => (
            <path
              key={`area-${cveId}`}
              d={buildAreaPath(trends, cveId, width, height, padding)}
              fill={`url(#grad-${idx})`}
            />
          ))}

          {/* Lines */}
          {cveIds.map((cveId, idx) => (
            <path
              key={cveId}
              d={buildPath(trends, cveId, width, height, padding)}
              fill="none"
              stroke={GRADIENT_FALLBACKS[idx % GRADIENT_FALLBACKS.length]}
              strokeWidth={2}
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          ))}

          {/* End dots */}
          {cveIds.map((cveId, idx) => {
            const lastTrend = trends[trends.length - 1];
            const values = trends.map((t) => t.scores[cveId]);
            const min = Math.min(...values) - 0.05;
            const max = Math.max(...values) + 0.05;
            const x = width - padding;
            const y =
              height -
              padding -
              ((lastTrend.scores[cveId] - min) / (max - min)) *
                (height - padding * 2);
            return (
              <circle
                key={`dot-${cveId}`}
                cx={x}
                cy={y}
                r={3}
                fill={GRADIENT_FALLBACKS[idx % GRADIENT_FALLBACKS.length]}
              />
            );
          })}
        </svg>

        {/* Legend */}
        <div className="mt-3 pt-3 border-t border-border/30 flex flex-wrap gap-4">
          {cveIds.map((cveId, idx) => {
            const lastScore = trends[trends.length - 1].scores[cveId];
            return (
              <div key={cveId} className="flex items-center gap-2">
                <div
                  className="h-2 w-2 rounded-full"
                  style={{
                    backgroundColor:
                      CHART_COLORS[idx % CHART_COLORS.length],
                  }}
                />
                <span className="font-mono text-[11px] text-muted-foreground">
                  {cveId}
                </span>
                <span
                  className="font-mono text-[11px] font-medium"
                  style={{
                    color: CHART_COLORS[idx % CHART_COLORS.length],
                  }}
                >
                  {lastScore.toFixed(3)}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
