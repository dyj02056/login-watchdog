# login-watchdog의 로컬 Docker 실습망 전용 공격 상자
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# nmap과 hping3는 제한된 포트 스캔과 SYN 재현에 사용한다.
# iproute2는 실습망 주소와 경로를 점검할 때 사용한다.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        hping3 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY netwatch/attacker/requirements.txt \
    /app/netwatch/attacker/requirements.txt

RUN pip install --no-cache-dir \
    -r /app/netwatch/attacker/requirements.txt

# 기존 시뮬레이터는 수정하지 않고 이미지 내부로 복사한다.
COPY scripts/simulation /app/scripts/simulation

COPY netwatch/attacker/lw.py \
    /app/netwatch/attacker/lw.py

ENTRYPOINT ["python", "/app/netwatch/attacker/lw.py"]