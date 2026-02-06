FROM caddy:2-alpine

COPY docker/Caddyfile /etc/caddy/Caddyfile
COPY docs/ui_poc /srv/ui

EXPOSE 4100
