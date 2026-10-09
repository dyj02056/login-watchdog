"use client";

// Chart — ECharts를 React에 붙이는 얇은 래퍼. 필요한 차트 종류만 등록해서(트리 셰이킹) 번들을 줄인다.
// 색은 CSS 토큰(tokens.css)에서 읽어서, 차트와 나머지 화면의 색이 한 곳에서만 정해지게 한다.
import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, HeatmapChart, LineChart, PieChart, SankeyChart } from "echarts/charts";
import { GridComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";
import styles from "./Chart.module.css";

echarts.use([BarChart, HeatmapChart, LineChart, PieChart, SankeyChart, GridComponent, TooltipComponent, VisualMapComponent, CanvasRenderer]);

export type Theme = ReturnType<typeof readTheme>;

export function readTheme() {
  const css = getComputedStyle(document.documentElement);
  const get = (name: string) => css.getPropertyValue(name).trim();
  return {
    font: get("--font-body"),
    mono: get("--font-num"),
    ink0: get("--ink-0"),
    ink1: get("--ink-1"),
    ink2: get("--ink-2"),
    line: get("--line"),
    lineStrong: get("--line-strong"),
    bg1: get("--bg-1"),
    bg2: get("--bg-2"),
    bg3: get("--bg-3"),
    cyan: get("--cyan"),
    signal: get("--signal"),
    today: get("--series-today"),
    yesterday: get("--series-yesterday"),
    week: get("--series-week"),
    critical: get("--sev-critical"),
    high: get("--sev-high"),
    medium: get("--sev-medium"),
  };
}

/** 모든 차트가 공유하는 툴팁 모양 */
export function tooltipBase(t: Theme) {
  return {
    backgroundColor: t.bg2,
    borderColor: t.lineStrong,
    borderWidth: 1,
    padding: [6, 10],
    textStyle: { color: t.ink0, fontFamily: t.font, fontSize: 12 },
    extraCssText: "border-radius:2px;box-shadow:0 6px 16px rgba(0,0,0,.45);",
  };
}

type Props = {
  build: (theme: Theme) => EChartsCoreOption;
  /** 스크린 리더용 설명. 차트가 무엇을 보여주는지 한 문장으로 */
  label: string;
  /** build가 의존하는 값. 바뀔 때만 다시 그린다 */
  deps: unknown[];
  className?: string;
};

export function Chart({ build, label, deps, className }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  const buildRef = useRef(build);
  buildRef.current = build;

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    const instance = echarts.init(element, undefined, { renderer: "canvas" });
    chart.current = instance;
    const observer = new ResizeObserver(() => instance.resize());
    observer.observe(element);
    return () => {
      observer.disconnect();
      instance.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    chart.current?.setOption(buildRef.current(readTheme()), { notMerge: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return <div ref={host} className={`${styles.chart} ${className ?? ""}`} role="img" aria-label={label} />;
}
