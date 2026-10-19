# Scapy 기반 L4 측정기 실행 환경
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Scapy의 BPF 필터(filter="tcp") 사용에 필요한 libpcap을 설치한다.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY detector_core.py ./
COPY l4_detector.py ./

CMD ["python", "-u", "l4_detector.py"]