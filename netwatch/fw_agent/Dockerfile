# ============================================================================
# netwatch/fw_agent/Dockerfile — fw-agent(L4 차단 실행기) 이미지 (C1-3)
#
# - python:3.12-alpine: 이 프로그램은 requests 하나만 쓰므로 가장 작은 이미지로 충분하다.
# - ipset·iptables: 실제 차단 명령. 컨테이너는 docker-compose에서 network_mode: service:gateway와
#   cap_add: NET_ADMIN으로 gateway의 네트워크 공간에 규칙을 건다(호스트 방화벽은 바꾸지 않음).
# - 비밀값(NET_AGENT_SECRET)은 이미지에 넣지 않고 실행할 때 환경 변수로만 받는다. Supabase 키는
#   아예 받지 않는다(상위 계획서 P6 — NET_ADMIN 컨테이너에는 DB 키를 주지 않는다).
# ============================================================================
FROM python:3.12-alpine

RUN apk add --no-cache ipset iptables

# print 로그가 버퍼에 쌓이지 않고 바로 docker compose logs에 보이게 한다(장애 확인용).
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fw_agent.py .

CMD ["python", "fw_agent.py"]
