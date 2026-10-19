# Suricata·Scapy 경보 파일을 내부 API로 전달하는 shipper 실행 환경
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY netwatch/shipper/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY netwatch/shipper/eve_shipper.py ./eve_shipper.py

CMD ["python", "/app/eve_shipper.py"]