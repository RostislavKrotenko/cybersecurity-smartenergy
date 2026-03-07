FROM python:3.11-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY services/db_writer/app.py /work/app.py
CMD ["python", "app.py"]
