FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

RUN apt-get update && apt-get install -y --no-install-recommends dnsutils curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

ENV ETM_CONTAINER=1
ENV ETM_USE_PLAIN_CREDENTIALS=1

RUN mkdir -p /app/data /app/logs /app/reports

EXPOSE 8080

ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/app/docker/entrypoint.ps1"]
