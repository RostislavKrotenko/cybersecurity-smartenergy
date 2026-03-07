FROM python:3.11-slim
WORKDIR /work
# No extra deps needed -- stdlib only
COPY services/network_sim/app.py /work/app.py
CMD ["python", "app.py"]
