// next build(정적 내보내기) 뒤에 한 번 돈다. 결과물을 Flask가 서빙하는 자리로 옮긴다.
//   out/**/*.html  → ../spa/**      화면 껍데기(helpers/spa.py의 SPA_PAGES가 가리킨다)
//   out/_next      → ../public/_next  해시가 붙은 JS·CSS·폰트(Flask가 public/을 "/"로 서빙하고, Vercel은 CDN이 서빙한다)
//   out/icon.svg   → ../public/icon.svg
// 그리고 이 사이트의 CSP(script-src 'self', style-src 'self')를 깨는 것이 HTML에 섞여 들어갔는지 검사한다.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(web, "out");
const spaDir = join(web, "..", "spa");
const publicDir = join(web, "..", "public");

// 404.html(app/not-found.tsx)은 Flask가 404 응답 본문으로 쓰므로 spa/로 옮긴다. _not-found.html은 같은 내용의 중복이라 건너뛴다.
const SKIP = new Set(["_not-found.html"]);

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name === "_next") continue;
      yield* walk(full);
    } else {
      yield full;
    }
  }
}

if (!existsSync(out)) throw new Error("out/ 이 없습니다. next build가 먼저 성공해야 합니다.");

rmSync(spaDir, { recursive: true, force: true });
rmSync(join(publicDir, "_next"), { recursive: true, force: true });
mkdirSync(spaDir, { recursive: true });

const problems = [];
let pages = 0;
for (const file of walk(out)) {
  const rel = relative(out, file).split(sep).join("/");
  if (!rel.endsWith(".html") || SKIP.has(rel)) continue;
  const html = readFileSync(file, "utf8");
  // 인라인 style 속성·<style> 태그는 CSP(style-src 'self')가 막는다.
  if (/<style[\s>]/i.test(html)) problems.push(`${rel}: <style> 태그`);
  if (/\sstyle="[^"]+"/i.test(html.replace(/<script[\s\S]*?<\/script>/g, ""))) problems.push(`${rel}: 인라인 style 속성`);
  // 인라인 이벤트 핸들러(onclick= 등)는 script-src 'self'가 막는다.
  if (/\son[a-z]+="/i.test(html.replace(/<script[\s\S]*?<\/script>/g, ""))) problems.push(`${rel}: 인라인 이벤트 핸들러`);
  const target = join(spaDir, rel);
  mkdirSync(dirname(target), { recursive: true });
  cpSync(file, target);
  pages += 1;
}

cpSync(join(out, "_next"), join(publicDir, "_next"), { recursive: true });
if (existsSync(join(out, "icon.svg"))) cpSync(join(out, "icon.svg"), join(publicDir, "icon.svg"));

if (problems.length) {
  console.error("CSP를 깨는 마크업이 있습니다:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log(`postbuild: 화면 ${pages}개 → spa/, 정적 파일 → public/_next`);
