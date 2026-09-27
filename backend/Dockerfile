FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ARG TARGETARCH
ARG AMASS_VERSION=5.1.1
ARG NUCLEI_VERSION=3.11.1

WORKDIR /app

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl nmap tar unzip; \
    case "${TARGETARCH:-amd64}" in \
      amd64) scanner_arch="amd64" ;; \
      arm64) scanner_arch="arm64" ;; \
      *) echo "Unsupported scanner architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_${scanner_arch}.tar.gz" -o /tmp/amass.tar.gz; \
    tar -xzf /tmp/amass.tar.gz -C /tmp; \
    install -m 0755 "/tmp/amass_linux_${scanner_arch}/amass" /usr/local/bin/amass; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${scanner_arch}.zip" -o /tmp/nuclei.zip; \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    nuclei -update-templates -update-template-dir /root/nuclei-templates; \
    apt-get clean; \
    find /tmp -mindepth 1 -maxdepth 1 -exec rm -rf {} +; \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev]"

COPY alembic.ini ./
COPY alembic ./alembic
COPY tests ./tests

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
