FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY agentic_soc ./agentic_soc
RUN pip install --no-cache-dir .

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready')"

CMD ["uvicorn", "agentic_soc.main:app", "--host", "0.0.0.0", "--port", "8000"]
