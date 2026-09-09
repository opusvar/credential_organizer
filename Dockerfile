FROM python:3.11-slim

# Install Bitwarden CLI
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip \
    && curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o /tmp/bw.zip \
    && unzip /tmp/bw.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/bw \
    && rm /tmp/bw.zip \
    && apt-get remove -y curl unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir -e .

# Non-root user — bw writes session state to ~/.config/Bitwarden CLI
RUN useradd -m cvc
USER cvc
ENV HOME=/home/cvc

ENTRYPOINT []
