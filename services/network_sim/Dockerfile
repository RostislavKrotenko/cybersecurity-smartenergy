FROM python:3.11-slim
WORKDIR /work
# Додаткові залежності не потрібні, використовується лише stdlib.
COPY services/network_sim/app.py /work/app.py
CMD ["python", "app.py"]
