# Suricata·Scapy 경보 파일을 내부 API로 전달하는 shipper 실행 환경
# 빌드 컨텍스트는 이 폴더(./netwatch/shipper)다. 루트 .dockerignore가 netwatch/를
# 통째로 빼므로(앱 이미지용), 루트를 컨텍스트로 쓰면 eve_shipper.py를 복사하지 못한다.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY eve_shipper.py ./eve_shipper.py

CMD ["python", "/app/eve_shipper.py"]
