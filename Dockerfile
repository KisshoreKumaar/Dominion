# GRIDSENTINEL container.
# Python 3.12 (not the host's 3.14) so the full scientific stack installs from
# manylinux wheels rather than compiling from source.
FROM python:3.12-slim

# libgomp1 is needed by scikit-learn / scipy OpenMP at runtime on slim images.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Then the source.
COPY . .

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# RTU Modbus ports (5020-5027) + live API/WebSocket (8000).
EXPOSE 8000 5020 5021 5022 5023 5024 5025 5026 5027

# Default: serve the live grid feed. Override for other demo modes, e.g.:
#   docker compose run --rm gridsentinel python scripts/run_demo.py --scada
CMD ["python", "scripts/run_demo.py", "--api", "--port", "8000"]
