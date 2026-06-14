# /etc/nginx/sites-available/house.tuesday.md

upstream tuesday_house_api {
    server 127.0.0.1:5002;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name house.tuesday.md;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        default_type "text/plain";
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name house.tuesday.md;

    ssl_certificate     /etc/letsencrypt/live/house.tuesday.md/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/house.tuesday.md/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    client_max_body_size 512M;
    client_body_timeout 300s;

    access_log /var/log/nginx/house.tuesday.md.access.log;
    error_log  /var/log/nginx/house.tuesday.md.error.log warn;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location = / {
        return 200 "Tuesday's House API is alive.\n";
        add_header Content-Type text/plain;
    }

    location /api/ {
        proxy_pass http://tuesday_house_api;

        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header Authorization     $http_authorization;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_connect_timeout 30s;

        proxy_buffering off;
        proxy_request_buffering off;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }
}
