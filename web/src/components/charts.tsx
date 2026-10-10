"use client";

// charts.tsx — 관제 화면에서 쓰는 차트 6종. 값이 비었을 때의 안내는 부르는 쪽(화면)이 정한다.
import { Chart, tooltipBase } from "./Chart";
import type { Theme } from "./Chart";
import { actionLabel, eventTypeLabel } from "@/lib/labels";
import { formatCount, formatDayWithWeekday, formatMonthDay } from "@/lib/format";
import type { Stats } from "@/lib/types";

const HOURS = Array.from({ length: 24 }, (_, hour) => String(hour).padStart(2, "0"));

function axisText(t: Theme) {
  return { color: t.ink2, fontFamily: t.mono, fontSize: 11 };
}

function fade(color: string) {
  return {
    type: "linear" as const,
    x: 0,
    y: 0,
    x2: 0,
    y2: 1,
    colorStops: [
      { offset: 0, color: `${color}55` },
      { offset: 1, color: `${color}00` },
    ],
  };
}

/** 시간대별 탐지량: 오늘(면적) · 어제 · 지난주 같은 요일(점선) */
export function HourlyTrend({ hourly }: { hourly: Stats["hourly"] }) {
  return (
    <Chart
      label="시간대별 탐지량. 오늘, 어제, 지난주 같은 요일을 비교하는 꺾은선 그래프"
      deps={[hourly]}
      build={(t) => ({
        animationDuration: 500,
        grid: { left: 34, right: 12, top: 12, bottom: 24 },
        tooltip: { trigger: "axis", ...tooltipBase(t), axisPointer: { lineStyle: { color: t.lineStrong } } },
        xAxis: {
          type: "category",
          boundaryGap: false,
          data: HOURS,
          axisTick: { show: false },
          axisLine: { lineStyle: { color: t.lineStrong } },
          axisLabel: { ...axisText(t), interval: 1 },
        },
        yAxis: {
          type: "value",
          minInterval: 1,
          splitLine: { lineStyle: { color: t.line } },
          axisLabel: axisText(t),
        },
        series: [
          { name: "지난주", type: "line", data: hourly.last_week, showSymbol: false, smooth: 0.2, lineStyle: { width: 1.5, type: "dashed", color: t.week }, itemStyle: { color: t.week } },
          { name: "어제", type: "line", data: hourly.yesterday, showSymbol: false, smooth: 0.2, lineStyle: { width: 1.5, color: t.yesterday }, itemStyle: { color: t.yesterday } },
          {
            name: "오늘",
            type: "line",
            data: hourly.today,
            showSymbol: false,
            smooth: 0.2,
            lineStyle: { width: 2.5, color: t.today },
            itemStyle: { color: t.today },
            areaStyle: { color: fade(t.today) },
            z: 3,
          },
        ],
      })}
    />
  );
}

/** 공격 상세용: 오늘은 막대, 어제·지난주는 선. 같은 데이터를 다른 눈으로 본다. */
export function HourlyMixed({ hourly }: { hourly: Stats["hourly"] }) {
  return (
    <Chart
      label="시간대별 탐지량. 오늘은 막대, 어제와 지난주 같은 요일은 선으로 비교"
      deps={[hourly]}
      build={(t) => ({
        animationDuration: 500,
        grid: { left: 36, right: 12, top: 14, bottom: 24 },
        tooltip: { trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: `${t.cyan}14` } }, ...tooltipBase(t) },
        xAxis: { type: "category", data: HOURS, axisTick: { show: false }, axisLine: { lineStyle: { color: t.lineStrong } }, axisLabel: { ...axisText(t), interval: 1 } },
        yAxis: { type: "value", minInterval: 1, splitLine: { lineStyle: { color: t.line } }, axisLabel: axisText(t) },
        series: [
          { name: "오늘", type: "bar", barWidth: "52%", data: hourly.today, itemStyle: { color: t.today } },
          { name: "어제", type: "line", data: hourly.yesterday, showSymbol: false, smooth: 0.2, lineStyle: { width: 1.75, color: t.yesterday }, itemStyle: { color: t.yesterday } },
          { name: "지난주", type: "line", data: hourly.last_week, showSymbol: false, smooth: 0.2, lineStyle: { width: 1.5, type: "dashed", color: t.week }, itemStyle: { color: t.week } },
        ],
      })}
    />
  );
}

/** 최근 7일 로그 발생량(막대). 오늘은 아직 쌓이는 중이라 속이 빈 막대로 구분한다. */
export function DailyVolume({ volume }: { volume: Stats["log_volume"] }) {
  return (
    <Chart
      label="최근 7일 날짜별 로그 발생량 막대 그래프"
      deps={[volume]}
      build={(t, { width }) => ({
        animationDuration: 500,
        grid: { left: 40, right: 8, top: 22, bottom: 34 },
        tooltip: { trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: `${t.cyan}14` } }, ...tooltipBase(t) },
        xAxis: {
          type: "category",
          // 좁은 화면에서는 요일까지 붙이면 라벨이 서로 겹치므로 월/일만 보여준다
          data: volume.map((v) => (width < 480 ? formatMonthDay(v.day) : formatDayWithWeekday(v.day))),
          axisTick: { show: false },
          axisLine: { lineStyle: { color: t.lineStrong } },
          axisLabel: { ...axisText(t), fontSize: 10, interval: 0 },
        },
        yAxis: { type: "value", splitLine: { lineStyle: { color: t.line } }, axisLabel: axisText(t) },
        series: [
          {
            type: "bar",
            barWidth: "46%",
            data: volume.map((v) => ({
              value: v.count,
              itemStyle: v.live
                ? { color: `${t.cyan}33`, borderColor: t.cyan, borderWidth: 1.5 }
                : { color: t.yesterday },
            })),
            label: { show: true, position: "top", color: t.ink1, fontFamily: t.mono, fontSize: 11 },
          },
        ],
      })}
    />
  );
}

/** 공격자 IP × 날짜 히트맵 */
export function IpHeatmap({ heatmap }: { heatmap: Stats["heatmap"] }) {
  return (
    <Chart
      label="최근 7일 공격자 IP별 날짜별 이벤트 건수 히트맵"
      deps={[heatmap]}
      build={(t) => {
        const data: [number, number, number][] = [];
        heatmap.cells.forEach((row, y) => row.forEach((value, x) => data.push([x, y, value])));
        const max = Math.max(1, ...heatmap.cells.flat());
        return {
          animationDuration: 400,
          grid: { left: 104, right: 8, top: 6, bottom: 26 },
          tooltip: {
            ...tooltipBase(t),
            formatter: (p: { value: [number, number, number] }) =>
              `${heatmap.ips[p.value[1]]}<br/>${formatMonthDay(heatmap.days[p.value[0]])} · <b>${p.value[2]}</b>건`,
          },
          xAxis: {
            type: "category",
            data: heatmap.days.map(formatMonthDay),
            splitArea: { show: false },
            axisTick: { show: false },
            axisLine: { lineStyle: { color: t.lineStrong } },
            axisLabel: { ...axisText(t), fontSize: 10 },
          },
          yAxis: {
            type: "category",
            data: heatmap.ips,
            inverse: true,
            axisTick: { show: false },
            axisLine: { show: false },
            axisLabel: { ...axisText(t), color: t.ink1, fontSize: 11 },
          },
          visualMap: { show: false, min: 0, max, inRange: { color: [t.bg2, `${t.cyan}66`, t.cyan] } },
          series: [
            {
              type: "heatmap",
              data,
              itemStyle: { borderColor: t.bg1, borderWidth: 2 },
              label: {
                show: true,
                color: t.ink0,
                fontFamily: t.mono,
                fontSize: 11,
                formatter: (p: { value: [number, number, number] }) => (p.value[2] > 0 ? String(p.value[2]) : ""),
              },
              emphasis: { itemStyle: { borderColor: t.ink0 } },
            },
          ],
        };
      }}
    />
  );
}

type FlowKind = "source" | "type" | "action";

// 공격 유형마다 색 하나를 돌려 쓴다. 그 유형으로 들어오고 나가는 띠가 같은 색이라 한 줄기로 따라가진다.
const FLOW_TYPE_COLORS = ["#3cc8f0", "#e9568f", "#f2d04b", "#a78bfa", "#ff9a3c", "#34e08c", "#5eead4", "#f472b6"];

/** 조치는 심각도 색: 알림은 약하게, 요청 거부는 중간, 잠금은 강하게. */
function flowActionColor(t: Theme, action: string): string {
  if (action === "ALERTED") return t.cyan;
  if (action === "REJECTED") return t.high;
  return t.critical;
}

/** 흐름도(Sankey). 왼쪽 출발(IP·국가) → 공격 유형 → 조치. */
export function FlowChart({ links, sourceLabel }: { links: { source: string; target: string; value: number }[]; sourceLabel?: string }) {
  return (
    <Chart
      label={`${sourceLabel ?? "출발지"}에서 공격 유형과 조치로 이어지는 흐름도`}
      deps={[links]}
      build={(t) => {
        const kinds = new Map<string, FlowKind>();
        for (const link of links) {
          if (!kinds.has(link.source)) kinds.set(link.source, "source");
          kinds.set(link.target, link.target.startsWith("조치:") ? "action" : "type");
        }
        // 유형 노드는 source로 먼저 등록됐을 수 있으므로(유형 → 조치 링크) 한 번 더 바로잡는다.
        for (const link of links) if (link.target.startsWith("조치:")) kinds.set(link.source, "type");
        const depth: Record<FlowKind, number> = { source: 0, type: 1, action: 2 };

        // 노드 합계(들어온 양과 나간 양 중 큰 쪽) — 라벨에 건수로 붙인다.
        const inSum = new Map<string, number>();
        const outSum = new Map<string, number>();
        for (const link of links) {
          inSum.set(link.target, (inSum.get(link.target) ?? 0) + link.value);
          outSum.set(link.source, (outSum.get(link.source) ?? 0) + link.value);
        }
        const total = (name: string) => Math.max(inSum.get(name) ?? 0, outSum.get(name) ?? 0);

        const typeColor = new Map<string, string>();
        for (const [name, kind] of kinds) if (kind === "type") typeColor.set(name, FLOW_TYPE_COLORS[typeColor.size % FLOW_TYPE_COLORS.length]);
        const nodeColor = (name: string, kind: FlowKind) =>
          kind === "type" ? typeColor.get(name)! : kind === "action" ? flowActionColor(t, name.slice(3)) : t.week;
        const display = (name: string, kind: FlowKind) =>
          kind === "action" ? actionLabel(name.slice(3)) : kind === "type" ? eventTypeLabel(name) : name;

        return {
          animationDuration: 500,
          tooltip: { trigger: "item", ...tooltipBase(t) },
          series: [
            {
              type: "sankey",
              left: 6,
              right: 150,
              top: 8,
              bottom: 8,
              nodeWidth: 14,
              nodeGap: 14,
              draggable: false,
              // 가리킨 경로만 밝게, 나머지는 흐리게
              emphasis: { focus: "adjacency", lineStyle: { opacity: 0.85 } },
              blur: { lineStyle: { opacity: 0.06 }, itemStyle: { opacity: 0.35 } },
              data: [...kinds].map(([name, kind]) => ({
                name,
                depth: depth[kind],
                itemStyle: { color: nodeColor(name, kind) },
                label: {
                  formatter: `${display(name, kind)}  {n|${formatCount(total(name))}건}`,
                  rich: { n: { color: t.ink1, fontFamily: t.mono, fontSize: 11 } },
                  color: t.ink0,
                  fontFamily: t.font,
                  fontSize: 12,
                  fontWeight: 500,
                },
              })),
              links: links.map((link) => {
                // 띠 색은 연결된 "유형"의 색을 따른다.
                const typeName = typeColor.has(link.target) ? link.target : link.source;
                return { ...link, lineStyle: { color: typeColor.get(typeName) ?? t.week, opacity: 0.5 } };
              }),
              lineStyle: { curveness: 0.5 },
              // 노드가 많아 라벨이 겹치면 작은 노드의 라벨을 숨긴다(값은 가리키면 툴팁으로 확인)
              labelLayout: { hideOverlap: true },
            },
          ],
        };
      }}
    />
  );
}

type Named = { name: string; count: number }[];

/** 가로 막대 Top N. 이름이 길면 왼쪽에 그대로 보인다. */
export function TopBars({ items, tone, format, label }: { items: Named; tone: "cyan" | "pink" | "green"; format?: (name: string) => string; label: string }) {
  return (
    <Chart
      label={label}
      deps={[items, tone]}
      build={(t) => {
        const rows = [...items].reverse();
        const color = { cyan: t.cyan, pink: t.yesterday, green: t.signal }[tone];
        return {
          animationDuration: 400,
          grid: { left: 8, right: 44, top: 4, bottom: 4, containLabel: true },
          tooltip: { trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: `${t.cyan}14` } }, ...tooltipBase(t) },
          xAxis: { type: "value", show: false },
          yAxis: {
            type: "category",
            data: rows.map((r) => (format ? format(r.name) : r.name)),
            axisTick: { show: false },
            axisLine: { show: false },
            axisLabel: { color: t.ink1, fontFamily: t.font, fontSize: 11, width: 110, overflow: "truncate" },
          },
          series: [
            {
              type: "bar",
              barWidth: "56%",
              data: rows.map((r) => r.count),
              itemStyle: { color },
              label: { show: true, position: "right", color: t.ink0, fontFamily: t.mono, fontSize: 11 },
            },
          ],
        };
      }}
    />
  );
}

const PATH_COLORS = ["#3cc8f0", "#e9568f", "#34e08c", "#ff9a3c", "#a78bfa"];
// 미확인 쪽 도넛은 큰 도넛과 색이 겹쳐 보이지 않게 옅은 색을 쓴다. "기타"는 마지막에 회색으로.
const UNKNOWN_COLORS = ["#7dd3fc", "#fda4af", "#fcd34d", "#c4b5fd"];
const UNKNOWN_OTHER = "기타";
const UNKNOWN_NAME = "미확인";

/**
 * 도넛: 대상 경로 비중. 경로가 기록되지 않은 이벤트는 큰 도넛의 한 조각("미확인")으로 두고,
 * 그 조각에서 시작하는 화살표로 이어진 작은 도넛(큰 도넛의 75%)에서 공격 유형별로 쪼개 보여준다.
 * 위치는 전부 px로 계산한다 — 화살표 끝점과 가운데 문구가 도넛 중심에 정확히 맞아야 해서 퍼센트를 쓰지 않는다.
 */
export function PathDonut({ items, pathless, pathlessTotal }: { items: Named; pathless: Named; pathlessTotal: number }) {
  return (
    <Chart
      label="공격 대상 경로별 비중 도넛 차트와, 경로가 확인되지 않은(미확인) 이벤트의 공격 유형별 도넛 차트"
      deps={[items, pathless, pathlessTotal]}
      build={(t, { width, height }) => {
        const pathTotal = items.reduce((sum, item) => sum + item.count, 0);
        const hasPaths = items.length > 0;
        const hasUnknown = pathlessTotal > 0;
        const both = hasPaths && hasUnknown;
        const narrow = both && width < 640; // 좁으면 두 도넛을 위아래로 쌓는다

        const big = narrow ? { outer: 58, inner: 36 } : width < 480 ? { outer: 50, inner: 30 } : { outer: 96, inner: 58 };
        const small = { outer: Math.round(big.outer * 0.75), inner: Math.round(big.inner * 0.75) };
        const labelSpace = 130; // 도넛 바깥 라벨이 들어갈 좌우 여백
        // 칸이 넓어도 두 도넛 사이가 한없이 멀어지지 않게 묶음 폭을 제한하고 가운데에 둔다.
        const leftSpace = 150; // 큰 도넛 왼쪽 라벨은 경로 이름이라 더 길다
        const groupWidth = Math.min(width, 780); // 왼쪽 라벨 + 큰 도넛 + 화살표·작은 도넛 왼쪽 라벨 + 작은 도넛 + 오른쪽 라벨
        const left = (width - groupWidth) / 2;

        // 중심 좌표(px). 가로: 큰 도넛 왼쪽·작은 도넛 오른쪽. 세로: 큰 도넛 위·작은 도넛 아래.
        const cy = height * 0.52;
        const bigCenter = both
          ? narrow
            ? { x: width / 2, y: height * 0.27 }
            : { x: left + leftSpace + big.outer, y: cy }
          : { x: width / 2, y: cy };
        const smallCenter = hasPaths
          ? narrow
            ? { x: width / 2, y: height * 0.77 }
            : { x: left + groupWidth - labelSpace + 10 - small.outer, y: cy }
          : { x: width / 2, y: cy };

        // "미확인" 조각이 큰 도넛의 오른쪽(가로) 또는 아래쪽(세로) 한가운데에 오도록 시작 각도를 맞춘다 — 화살표가 그 조각에서 똑바로 나간다.
        const share = both ? pathlessTotal / (pathTotal + pathlessTotal) : 0;
        const startAngle = (narrow ? -90 : 0) + share * 180;

        const bigData = [
          ...(both
            ? [{ name: UNKNOWN_NAME, value: pathlessTotal, itemStyle: { color: t.week }, label: { show: false }, labelLine: { show: false } }]
            : []),
          ...items.map((item, index) => ({ name: item.name, value: item.count, itemStyle: { color: PATH_COLORS[index % PATH_COLORS.length] } })),
        ];
        const smallData = pathless.map((item, index) => ({
          name: eventTypeLabel(item.name),
          value: item.count,
          itemStyle: { color: item.name === UNKNOWN_OTHER ? t.week : UNKNOWN_COLORS[index % UNKNOWN_COLORS.length] },
        }));

        const pieBase = { type: "pie" as const, minAngle: 6, itemStyle: { borderColor: t.bg1, borderWidth: 2 }, labelLine: { lineStyle: { color: t.lineStrong } } };
        // 세로로 쌓은 좁은 화면에서는 도넛 좌우 여백이 라벨 폭을 정한다 — 고정 폭이면 오른쪽 라벨이 칸 밖으로 잘린다
        const sideLabel = Math.max(40, Math.floor(width / 2 - big.outer - 14));
        const labelBase = { color: t.ink1, fontFamily: t.font, fontSize: 11, overflow: "truncate" as const };

        // 화살표: 큰 도넛의 "미확인" 조각 바깥 가장자리에서 시작해 작은 도넛 바깥 가장자리 바로 앞에서 끝난다.
        // 그룹을 시작점에 놓고 +x 방향으로 그린 뒤, 세로 배치면 90도 돌려 아래쪽을 향하게 한다.
        const gap = 6;
        const from = narrow ? { x: bigCenter.x, y: bigCenter.y + big.outer } : { x: bigCenter.x + big.outer, y: bigCenter.y };
        const length = Math.max(0, narrow ? smallCenter.y - small.outer - gap - from.y : smallCenter.x - small.outer - gap - from.x);

        return {
          animationDuration: 500,
          tooltip: { trigger: "item", ...tooltipBase(t) },
          series: [
            ...(hasPaths
              ? [
                  {
                    ...pieBase,
                    name: "대상 경로",
                    radius: [big.inner, big.outer],
                    center: [bigCenter.x, bigCenter.y],
                    startAngle,
                    label: { ...labelBase, width: width < 480 ? sideLabel : leftSpace - 25, formatter: "{b}" },
                    data: bigData,
                  },
                ]
              : []),
            ...(hasUnknown
              ? [
                  {
                    ...pieBase,
                    name: UNKNOWN_NAME,
                    radius: [small.inner, small.outer],
                    center: [smallCenter.x, smallCenter.y],
                    label: { ...labelBase, width: width < 480 ? sideLabel : labelSpace - 20, formatter: "{b}\n{c}건" },
                    tooltip: { formatter: (p: { name: string; value: number; percent: number }) => `${p.name}<br/>${p.value}건 · ${UNKNOWN_NAME} 중 ${p.percent}%` },
                    data: smallData,
                  },
                ]
              : []),
          ],
          graphic: {
            elements: [
              ...(both && length > 12
                ? [
                    {
                      type: "group",
                      x: from.x,
                      y: from.y,
                      rotation: narrow ? -Math.PI / 2 : 0, // zrender는 시계 반대 방향이 +라서 -90도가 아래쪽
                      silent: true,
                      children: [
                        { type: "circle", shape: { cx: 0, cy: 0, r: 3 }, style: { fill: t.ink1 } },
                        { type: "polyline", shape: { points: [[0, 0], [length - 2, 0]] }, style: { stroke: t.ink1, lineWidth: 1.5, fill: "none" } },
                        { type: "polygon", shape: { points: [[length, 0], [length - 8, -4.5], [length - 8, 4.5]] }, style: { fill: t.ink1 } },
                      ],
                    },
                  ]
                : []),
              ...(hasUnknown
                ? [
                    {
                      type: "text",
                      silent: true,
                      x: smallCenter.x,
                      y: smallCenter.y,
                      style: {
                        text: `${UNKNOWN_NAME}\n${formatCount(pathlessTotal)}건`,
                        textAlign: "center",
                        textVerticalAlign: "middle",
                        fill: t.ink1,
                        font: `600 11px ${t.font}`,
                        lineHeight: 15,
                      },
                    },
                  ]
                : []),
            ],
          },
        };
      }}
    />
  );
}
