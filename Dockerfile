FROM python:3.11-slim

# =========================
# SISTEMA / DEPENDÊNCIAS
# =========================
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    gcc \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# =========================
# INSTALAR NUCLEI
# =========================
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip \
    && unzip nuclei_3.3.5_linux_amd64.zip \
    && chmod +x nuclei \
    && mv nuclei /usr/local/bin/

# =========================
# BAIXAR TEMPLATES (FORÇADO)
# =========================
RUN mkdir -p /root/.nuclei-templates \
    && wget https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip \
    && unzip main.zip \
    && mv nuclei-templates-main/* /root/.nuclei-templates/ \
    && rm -rf main.zip nuclei-templates-main

# =========================
# APP
# =========================
WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install weasyprint

ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates

# =========================
# START
# =========================
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
