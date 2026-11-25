FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    API_PORT=8000 \
    DATA_DIR=/data

RUN useradd --create-home --uid 1000 upb && mkdir -p /data && chown upb:upb /data
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN chown -R upb:upb /app
USER upb

VOLUME ["/data"]

# Un solo worker: el estado de la cadena vive en memoria del proceso.
CMD ["sh", "-c", "exec uvicorn api.app:app --host 0.0.0.0 --port ${API_PORT} --workers 1"]
