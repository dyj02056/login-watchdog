// theme.js — 우측 상단 "라이트/다크 모드" 버튼 동작
//
// 이 파일은 두 부분으로 나뉜다.
// 1) 즉시 실행되는 부분(맨 위): 사용자가 예전에 골라둔 테마를 localStorage에서
//    읽어와 <html> 태그에 즉시 적용한다. DOMContentLoaded를 기다리지 않고
//    바로 실행해야 하는 이유는, 화면이 그려지기 전에 테마를 정해둬야
//    "잠깐 라이트모드로 번쩍였다가 다크모드로 바뀌는" 깜빡임을 막을 수
//    있기 때문이다. 그래서 <head> 안에서 다른 CSS/스크립트보다 먼저 불러온다.
// 2) DOMContentLoaded 이후 부분: 실제 버튼을 찾아 클릭 이벤트를 걸어준다.
(function () {
    try {
        var saved = localStorage.getItem("theme");
        if (saved === "light" || saved === "dark") {
            document.documentElement.setAttribute("data-theme", saved);
        }
    } catch (e) {
        // localStorage를 못 쓰는 환경(프라이빗 브라우징 등)이면 그냥
        // OS 설정을 따르는 자동 다크모드만 동작한다 — 에러를 띄우지 않는다.
    }
})();

document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;

    updateButtonLabel(btn);

    btn.addEventListener("click", function () {
        var isDark = currentlyDark();
        var next = isDark ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try {
            localStorage.setItem("theme", next);
        } catch (e) {}
        updateButtonLabel(btn);
    });
});

// 지금 화면이 다크모드인지 판단한다: 사용자가 직접 고른 값이 있으면 그 값을,
// 없으면 OS/브라우저의 다크모드 설정을 기준으로 삼는다.
function currentlyDark() {
    var current = document.documentElement.getAttribute("data-theme");
    if (current === "dark") return true;
    if (current === "light") return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function updateButtonLabel(btn) {
    btn.textContent = currentlyDark() ? "라이트 모드" : "다크 모드";
}
