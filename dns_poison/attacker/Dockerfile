FROM python:3.11-slim
WORKDIR /app
COPY attacker.py .
# Raw sockets need root — only acceptable in a controlled lab environment
CMD ["python3", "-u", "attacker.py"]
