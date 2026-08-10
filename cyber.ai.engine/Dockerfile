# Build context is the REPOSITORY ROOT, not cyber.ai.engine/, so that the
# cyber.contracts/ path dependency resolves. See docker-compose.yml.
#
#   docker build -f cyber.ai.engine/Dockerfile .

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /src/cyber.ai.engine

COPY cyber.contracts /src/cyber.contracts
COPY cyber.ai.engine/pyproject.toml cyber.ai.engine/poetry.lock cyber.ai.engine/poetry.toml /src/cyber.ai.engine/

RUN poetry install --only main --no-root

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/src/cyber.ai.engine/.venv/bin:${PATH}"

# Scanners the agents launch themselves: nmap for hosts, nuclei for web apps,
# dig/curl for URL checks. This image is a scanning tool by design, so it is
# also the image with the widest blast radius - keep the package list minimal.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        nmap \
        dnsutils \
        curl \
        unzip \
        ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Nuclei is fetched from its GitHub release. The checksum published alongside the
# asset is verified before unzipping: without it a corrupted or swapped download
# would be installed silently, which is a poor property for a security tool.
ARG NUCLEI_VERSION=3.3.10
RUN set -eux; \
    base="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"; \
    asset="nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    curl -fsSL "${base}/${asset}" -o "/tmp/${asset}"; \
    curl -fsSL "${base}/nuclei_${NUCLEI_VERSION}_checksums.txt" -o /tmp/checksums.txt; \
    grep " ${asset}\$" /tmp/checksums.txt > /tmp/asset.sha256; \
    cd /tmp && sha256sum -c asset.sha256; \
    unzip -o "/tmp/${asset}" -d /usr/local/bin nuclei; \
    rm -f "/tmp/${asset}" /tmp/checksums.txt /tmp/asset.sha256; \
    nuclei -version

RUN groupadd --system app && useradd --system --gid app --home-dir /src app

WORKDIR /src/cyber.ai.engine

COPY cyber.contracts /src/cyber.contracts
COPY cyber.ai.engine /src/cyber.ai.engine
COPY --from=builder /src/cyber.ai.engine/.venv /src/cyber.ai.engine/.venv

RUN chown -R app:app /src
USER app

# Nuclei ships without templates; fetch the official set so the webapp agent's
# self-launched scans can actually detect anything. Nuclei resolves its template
# store to $HOME/nuclei-templates (HOME=/src for the app user), so install there
# rather than in the config dir.
RUN mkdir -p /src/nuclei-templates \
    && nuclei -update-templates -silent \
    && test -n "$(ls -A /src/nuclei-templates)"

EXPOSE 8003

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
