// 운영 빌드는 정적 내보내기(out/)다 — 서버 없이 HTML/JS/CSS만 만들고, Flask(app.py)가 그것을 서빙한다
// (helpers/spa.py). 개발 서버(next dev)에서는 /api 요청을 로컬 Flask(5000번)로 넘긴다.
const isDev = process.env.NODE_ENV !== "production";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // 빌드마다 무작위 ID가 붙으면 내용이 같아도 spa/·public/_next가 매번 달라져 커밋·CI 비교가 의미 없어진다.
  generateBuildId: async () => "login-watchdog",
  images: { unoptimized: true },
  ...(isDev
    ? {
        async rewrites() {
          const flask = process.env.FLASK_ORIGIN ?? "http://127.0.0.1:5000";
          return [{ source: "/api/:path*", destination: `${flask}/api/:path*` }];
        },
      }
    : { output: "export", trailingSlash: false }),
};

export default nextConfig;
