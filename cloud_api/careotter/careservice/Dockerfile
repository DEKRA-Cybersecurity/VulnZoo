# careservice container — native build of labs/careotter/careservice.c
# Runs on standard glibc Linux with OpenWRT runtime stubs.

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        curl \
        netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/careotter

# Copy source from the labs tree (build context is project root)
COPY labs/careotter/careservice.c .

# Compile natively (no OpenWRT libs needed — careservice.c uses only POSIX)
RUN gcc -Wall -O2 -o careservice careservice.c

# Runtime directory tree mimicking OpenWRT
RUN mkdir -p /var/log /opt/careotter /etc/careotter /etc/init.d /etc/config

# Mock WiFi config (used by GET_NETWORK 0x03)
RUN echo -e "config wifi-iface\n\toption ssid 'LabNet'\n\toption key 'dummypsk123'" \
    > /etc/config/wireless

# Initial log / threshold files
RUN touch /var/log/careservice.log /opt/careotter_events.log \
    && printf "bpm_min=50\nbpm_max=120\nspo2_min=90\n" > /var/log/careotter.thresholds

# Alert endpoint config (used by EMERGENCY_ALERT 0x0C)
RUN echo "http://localhost:5002/api/device/alerts" > /etc/careotter/alert.conf

# OpenWRT runtime stubs
COPY cloud_api/careotter/careservice/stubs/uci /usr/local/bin/uci
COPY cloud_api/careotter/careservice/stubs/wifi /usr/local/bin/wifi
COPY cloud_api/careotter/careservice/stubs/iw /usr/local/bin/iw
RUN chmod +x /usr/local/bin/uci /usr/local/bin/wifi /usr/local/bin/iw

# Init.d stubs for restartable services
COPY cloud_api/careotter/careservice/stubs/init.d/sysntpd /etc/init.d/sysntpd
COPY cloud_api/careotter/careservice/stubs/init.d/medical-sensor /etc/init.d/medical-sensor
COPY cloud_api/careotter/careservice/stubs/init.d/careservice /etc/init.d/careservice
COPY cloud_api/careotter/careservice/stubs/init.d/ble-server /etc/init.d/ble-server
RUN chmod +x /etc/init.d/*

EXPOSE 9999

CMD ["./careservice"]
