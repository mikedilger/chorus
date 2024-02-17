server {
    listen 443 ssl;
    server_name chorus.example.com;
    #include snippets/snakeoil.conf;
    ssl_certificate /etc/letsencrypt/live/chorus.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chorus.example.com/privkey.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve secp521r1:secp384r1;
    ssl_ciphers EECDH+AESGCM:EECDH+AES256;

    keepalive_timeout 70;

    location /.well-known/acme-challenge {
        root /opt/chorus/var/www/;
   	    add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Headers *;
        add_header Access-Control-Allow-Methods *;
    }
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
	    proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }
}
