FROM python:3.12-slim

WORKDIR /app
COPY app.py .

ENV LISTEN_HOST=0.0.0.0
ENV LISTEN_PORT=8080
ENV LOG_PATH=/logs/events.log
ENV WEBHOOK_TOKEN=""

RUN useradd -r -u 1001 appuser
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["python", "app.py"]