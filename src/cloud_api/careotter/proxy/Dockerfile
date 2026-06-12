# CareOtter reverse proxy (API8 Security Misconfiguration + API9 Improper Inventory).
# One edge with two name-based vhosts (api.careotter.lab / beta.api.careotter.lab)
# in front of the API container. Enforces the "internal-only" ACL on the
# admin/debug/init surface, and rate-limits the OTP verify on the production name
# only (the beta name omits it = API9). The entrypoint picks the vulnerable or
# secure nginx config from VULNERABLE.
FROM nginx:1.27-alpine

# Drop the stock default; our entrypoint installs the chosen config here.
RUN rm -f /etc/nginx/conf.d/default.conf && mkdir -p /etc/nginx/staging

COPY nginx.vuln.conf nginx.secure.conf /etc/nginx/staging/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 5002
ENTRYPOINT ["/entrypoint.sh"]
