FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN grep -v '^pytest' requirements.txt > /tmp/prod-requirements.txt && \
    pip install --no-cache-dir -r /tmp/prod-requirements.txt

COPY . .

RUN mkdir -p metrics chroma_db

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
