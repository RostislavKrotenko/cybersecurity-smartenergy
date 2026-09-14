FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 smartenergy \
    && useradd \
        --uid 10001 \
        --gid smartenergy \
        --create-home \
        --shell /usr/sbin/nologin \
        smartenergy

COPY requirements.txt /work/requirements.txt

RUN python -m pip install \
    --no-cache-dir \
    -r /work/requirements.txt

COPY pyproject.toml README.md /work/
COPY src/ /work/src/
COPY config/ /work/config/

RUN python -m pip install --no-deps /work \
    && mkdir -p \
        /work/data/integration/control \
        /work/out \
        /work/logs \
    && chown -R smartenergy:smartenergy /work

USER smartenergy

EXPOSE 8000 8080

CMD ["python", "-m", "src.api", "--host", "0.0.0.0", "--port", "8000"]