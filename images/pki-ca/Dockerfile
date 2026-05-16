FROM alpine:3.20
RUN apk add --no-cache openssl bash curl
WORKDIR /work
COPY entrypoint.sh /entrypoint.sh
COPY ca-init.sh /ca-init.sh
RUN chmod +x /entrypoint.sh /ca-init.sh
EXPOSE 8081 8082
ENTRYPOINT ["/entrypoint.sh"]
