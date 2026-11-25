FROM python:3-slim
WORKDIR /app
COPY . .
ENTRYPOINT ["python3","nmap.py"]
