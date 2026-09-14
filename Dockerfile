FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 smartenergy && \
    useradd --uid 10001 --gid smartenergy --create-home --shell /usr/sbin/nologin smartenergy

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY src/ src/
COPY config/ config/

RUN pip install . && \
    mkdir -p data out logs && \
    chown -R smartenergy:smartenergy /work

USER smartenergy

CMD ["python", "-m", "src.api", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000
