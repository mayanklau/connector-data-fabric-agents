FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY agentic_soc ./agentic_soc
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "agentic_soc.main:app", "--host", "0.0.0.0", "--port", "8000"]
