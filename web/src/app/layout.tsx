import type { Metadata } from "next";
import { JetBrains_Mono, Noto_Sans_KR } from "next/font/google";
import "@/styles/tokens.css";
import "@/styles/base.css";
import "@/styles/controls.css";

// 한글 본문·제목: Noto Sans KR(가변). 숫자·IP·시각처럼 자릿수가 맞아야 하는 값: JetBrains Mono.
const sans = Noto_Sans_KR({ weight: ["400", "500", "600", "700"], display: "swap", preload: false, variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500", "700"], display: "swap", variable: "--font-mono" });

export const metadata: Metadata = {
  title: "로그인 워치독",
  description: "브루트포스·L7 공격 탐지와 대응 관제",
  icons: { icon: "/icon.svg" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko" className={`${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
