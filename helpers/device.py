# ============================================================================
# helpers/device.py — 비밀값 해시와 기기 쿠키(lw_dev)
#
# 예전 helpers.py(314줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from helpers import ...`로 가져다 쓴다(helpers/__init__.py가
# 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import hashlib
import secrets

from flask import request

import config


# ============================================================================
# 기기 쿠키(lw_dev) — IP 영구 잠금 "예외"를 요청한 그 기기에만 묶기 위한 표식 (guide34-a)
#
# 학교·회사처럼 여러 명이 같은 공인 IP(NAT)를 쓰는 곳에서, 피해자 A가 예외를 받았다고
# 하자. 예외를 아이디만으로 묶으면 같은 IP의 공격자가 A의 아이디로 무차별 대입을 계속할
# 수 있다. 예외를 "복구를 요청한 기기의 무작위 쿠키 해시"에까지 묶으면, 공격자에게는 그
# 쿠키가 없으므로 계속 막힌다. 쿠키 원문은 브라우저에만 있고 DB에는 해시만 저장한다.
# ============================================================================

def hash_secret(value: str) -> str:
    """토큰·코드·기기 쿠키를 DB에 저장하기 전에 SHA-256 지문(해시)으로 바꾼다.
    지문에서 원래 값을 되돌릴 수 없으므로 DB가 유출돼도 진짜 값은 새지 않는다."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_device_hash() -> str | None:
    """이번 요청의 기기 쿠키(lw_dev)를 해시로 바꿔 돌려준다. 쿠키가 없으면 None."""
    token = request.cookies.get(config.DEVICE_COOKIE_NAME)
    return hash_secret(token) if token else None


def new_device_token() -> str:
    """추측 불가능한 새 기기 쿠키 값을 만든다(secrets는 보안용 난수 — random은 예측 가능해 쓰면 안 된다)."""
    return secrets.token_urlsafe(32)


def set_device_cookie(response, token: str):
    """응답에 기기 쿠키를 심는다. HttpOnly(자바스크립트가 못 읽음) + SameSite=Lax이고,
    운영(HTTPS)에서는 Secure도 붙인다."""
    response.set_cookie(
        config.DEVICE_COOKIE_NAME,
        token,
        max_age=config.DEVICE_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=config.IS_PRODUCTION,
    )
    return response
