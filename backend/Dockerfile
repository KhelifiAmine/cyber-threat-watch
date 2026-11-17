FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch (CUDA 12.1) before requirements.txt so this 2.5 GB layer
# stays cached across requirements.txt changes. Only rebuilds when you change
# the torch version below. Run with --progress plain to see download progress.
RUN pip install torch --index-url https://download.pytorch.org/whl/cu121 --no-cache-dir

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright + Chromium dependencies (Debian Trixie renamed some font packages)
RUN apt-get update && apt-get install -y \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2t64 libxshmfence1 libxfixes3 fonts-unifont \
    && rm -rf /var/lib/apt/lists/* \
    && python -m playwright install chromium

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
