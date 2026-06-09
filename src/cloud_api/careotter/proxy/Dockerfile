# CareOtter reverse proxy (API8:2023 Security Misconfiguration lab).
# Fronts the API container and enforces the "internal-only" ACL on the
# admin/debug/init surface. The entrypoint picks the vulnerable or secure
# nginx config from VULNERABLE.
FROM nginx:1.27-alpine

# Drop the stock default; our entrypoint installs the chosen config here.
RUN rm -f /etc/nginx/conf.d/default.conf && mkdir -p /etc/nginx/staging

COPY nginx.vuln.conf nginx.secure.conf /etc/nginx/staging/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5002
ENTRYPOINT ["/entrypoint.sh"]
