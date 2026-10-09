"use client";

// charts.tsx — 관제 화면에서 쓰는 차트 6종. 값이 비었을 때의 안내는 부르는 쪽(화면)이 정한다.
import { Chart, tooltipBase } from "./Chart";
import type { Theme } from "./Chart";
import { actionLabel, eventTypeLabel } from "@/lib/labels";
import { formatDayWithWeekday, formatMonthDay } from "@/lib/format";
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
      build={(t) => ({
        animationDuration: 500,
        grid: { left: 40, right: 8, top: 22, bottom: 34 },
        tooltip: { trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: `${t.cyan}14` } }, ...tooltipBase(t) },
        xAxis: {
          type: "category",
          data: volume.map((v) => formatDayWithWeekday(v.day)),
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
        const color: Record<FlowKind, string> = { source: t.week, type: t.cyan, action: t.signal };
        const display = (name: string, kind: FlowKind) =>
          kind === "action" ? actionLabel(name.slice(3)) : kind === "type" ? eventTypeLabel(name) : name;
        return {
          animationDuration: 500,
          tooltip: { trigger: "item", ...tooltipBase(t) },
          series: [
            {
              type: "sankey",
              left: 6,
              right: 118,
              top: 6,
              bottom: 6,
              nodeWidth: 10,
              nodeGap: 10,
              draggable: false,
              emphasis: { focus: "adjacency" },
              data: [...kinds].map(([name, kind]) => ({
                name,
                depth: depth[kind],
                itemStyle: { color: color[kind] },
                label: { formatter: display(name, kind), color: t.ink0, fontFamily: t.font, fontSize: 11 },
              })),
              links,
              lineStyle: { color: "gradient", opacity: 0.32, curveness: 0.5 },
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

/** 도넛: 대상 경로 비중 */
export function PathDonut({ items }: { items: Named }) {
  return (
    <Chart
      label="공격 대상 경로별 비중 도넛 차트"
      deps={[items]}
      build={(t) => ({
        animationDuration: 500,
        color: [t.cyan, t.yesterday, t.signal, t.high, t.week],
        tooltip: { trigger: "item", ...tooltipBase(t) },
        series: [
          {
            type: "pie",
            radius: ["46%", "72%"],
            center: ["50%", "52%"],
            minAngle: 6,
            itemStyle: { borderColor: t.bg1, borderWidth: 2 },
            label: { color: t.ink1, fontFamily: t.font, fontSize: 11, formatter: "{b}" },
            labelLine: { lineStyle: { color: t.lineStrong } },
            data: items.map((i) => ({ name: i.name, value: i.count })),
          },
        ],
      })}
    />
  );
}
