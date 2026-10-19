# NULLVEIL Recon — defensive, read-only recon & reporting.
# Build:  docker build -t nullveil-recon .
# Run:    docker run --rm nullveil-recon https://example.com -a all
#
# The tool is read-only and makes outbound network calls to the scan target and
# to public intel APIs (only when --cve-live is enabled). Scan only targets you
# are authorized to test.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="NULLVEIL Recon" \
      org.opencontainers.image.description="Defensive, read-only attack-surface reconnaissance & reporting tool" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/nullveil0x/nullveil-recon"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Core runtime dependencies first (better layer caching).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The tool itself + docs.
COPY nullveil_recon.py ./
COPY README.md LICENSE ./

# Run as a non-root user.
RUN useradd --create-home --shell /usr/sbin/nologin nullveil \
    && mkdir -p /home/nullveil/.nullveil \
    && chown -R nullveil:nullveil /app /home/nullveil
USER nullveil

# Entrypoint forwards all args to the tool; mount a volume to keep reports.
ENTRYPOINT ["python", "/app/nullveil_recon.py"]
CMD ["--help"]
