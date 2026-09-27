FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netmon ./netmon

ENV NETMON_CONFIG=/config/config.yaml \
    NETMON_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8080 53/udp 53/tcp 2055/udp

# Runs as root inside the container because ARP scanning, packet capture and
# binding port 53 need NET_RAW / NET_ADMIN / NET_BIND_SERVICE; docker-compose
# grants only those capabilities.
ENTRYPOINT ["python", "-m", "netmon"]
CMD ["run"]
