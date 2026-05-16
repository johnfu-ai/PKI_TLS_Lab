FROM nginx:1.27-alpine
RUN apk add --no-cache bash openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY html/index.html /usr/share/nginx/html/index.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 4443 4444
ENTRYPOINT ["/entrypoint.sh"]
