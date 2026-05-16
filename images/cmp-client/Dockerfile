FROM alpine:3.20
RUN apk add --no-cache openssl bash
WORKDIR /work
COPY enroll.sh /usr/local/bin/enroll.sh
RUN chmod +x /usr/local/bin/enroll.sh
ENTRYPOINT ["/usr/local/bin/enroll.sh"]
