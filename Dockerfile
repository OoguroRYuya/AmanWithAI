# Image lab NDR — Eksperimen 2
# Satu image untuk SEMUA node (Client, Penyerang, Target, Collector).
# Semua tool + skrip sudah tertanam, jadi tidak hilang saat restart dan
# tidak perlu `apk add` tiap sesi.
FROM alpine:3.20

# --- Tool ---
# nmap, hping3 (dari edge/testing) untuk penyerang; python3/iperf3/dropbear
# untuk target; curl/iputils/openssh/iperf3 untuk klien; nfdump untuk collector.
RUN apk add --no-cache \
        bash iproute2 iputils curl openssh-client \
        python3 iperf3 dropbear \
        nmap nmap-scripting \
        nfdump \
    && apk add --no-cache hping3 --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

# --- Skrip (ditanam ke image, permanen) ---
COPY lab/scripts/ /root/skrip/
RUN chmod +x /root/skrip/*.sh && ln -s /root/skrip/*.sh /usr/local/bin/ 2>/dev/null; true

WORKDIR /root
CMD ["/bin/sh"]
