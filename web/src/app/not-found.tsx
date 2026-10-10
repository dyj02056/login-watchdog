import { AuthLayout } from "@/components/auth/AuthLayout";

// 존재하지 않는 주소(404). Flask의 handle_not_found(helpers/hooks.py)가 이 화면(spa/404.html)을 404 상태로 내려준다.
// 정적 화면이라 로그인 여부를 모른다 — 그래서 로그인·가입으로만 안내한다.
export default function NotFound() {
  return (
    <AuthLayout
      title="찾을 수 없는 주소입니다"
      lead="주소가 잘못되었거나 이동·삭제된 화면입니다. 주소를 다시 확인해 주세요."
      links={[
        { href: "/login", label: "로그인" },
        { href: "/signup", label: "회원가입" },
      ]}
    >
      <p className="notice" role="status">
        404 · 요청한 주소에 화면이 없습니다.
      </p>
    </AuthLayout>
  );
}
