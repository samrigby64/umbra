# A minimal Tor SOCKS proxy for the crawler to reach .onion services.
FROM alpine:3.20
RUN apk add --no-cache tor
COPY torrc /etc/tor/torrc
EXPOSE 9050
USER tor
CMD ["tor", "-f", "/etc/tor/torrc"]
