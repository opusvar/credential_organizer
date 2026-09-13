FROM python:3.11-slim

# Install Bitwarden CLI via npm (ARM64-compatible — the official binary is x86 only).
# npm global bin lands at /usr/local/bin/bw via the npm prefix.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && npm install -g @bitwarden/cli \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir -e .

# Non-root user — bw writes session state to ~/.config/Bitwarden CLI
RUN useradd -m -u 1000 cvc
USER cvc
ENV HOME=/home/cvc

ENTRYPOINT []
