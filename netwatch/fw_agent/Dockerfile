FROM python:3.12-alpine

RUN apk add --no-cache ipset iptables

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fw_agent.py .

CMD ["python", "fw_agent.py"]