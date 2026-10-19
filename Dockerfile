# Flask 애플리케이션 실행 환경
FROM python:3.12-slim

# 로그를 즉시 출력하고 불필요한 .pyc 파일 생성을 막는다.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 의존성 파일을 먼저 복사하여 Docker 빌드 캐시를 활용한다.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# .dockerignore에서 제외되지 않은 프로젝트 파일을 복사한다.
COPY . .

EXPOSE 5000

# 단일 프로세스 내부에서 여러 요청을 처리하도록 스레드를 사용한다.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "app:app"]