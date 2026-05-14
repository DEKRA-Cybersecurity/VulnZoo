#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <fcntl.h>

#define PORT          9999
#define MAGIC         0x43415245   /* "CARE" — IoT Gateway Protocol v4 */
#define ADMIN_TOKEN   "OtterMobile2026"
#define LOG_FILE      "/tmp/careservice.log"
#define EVENTS_FILE   "/tmp/careotter_events.log"
#define THRESH_FILE   "/tmp/careotter.thresholds"
#define ALERT_CONF    "/etc/careotter/alert.conf"
#define SENSOR_PORT   8081
#define _STRINGIFY(x) #x
#define STRINGIFY(x)  _STRINGIFY(x)

typedef struct {
    uint32_t magic;
    uint8_t  cmd;
    uint8_t  status;
    uint16_t len;
} __attribute__((packed)) igp_hdr_t;

/* Auth state global — persists between connections (embedded design flaw) */
int authenticated = 0;

/* ── Internal utilities ──────────────────────────────────────────────────── */

static void log_event(const char *msg) {
    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    time_t t = time(NULL);
    char line[256];
    int n = snprintf(line, sizeof(line), "[%ld] %s\n", (long)t, msg);
    write(fd, line, n);
    close(fd);
}

/* Validates OpenWRT service names: only [a-z0-9-], max 32 chars */
static int is_valid_service_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) > 32) return 0;
    for (const char *p = name; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') ||
               *p == '-'))
            return 0;
    }
    return 1;
}

/* ── TLV Parsers ─────────────────────────────────────────────────────────── */

/*
 * VULNERABILITY 2: Integer Underflow in preferences parser.
 * Real context: stores app preferences (language, theme, screen mode).
 * TLV format: [Type(1)|Len(1)|Value(n)]
 *   Type 0xAA = visual theme name
 *   Type 0xAB = language code (es/en/fr)
 *   Type 0xAC = screen mode (0=day, 1=night)
 *
 * The generic parser is maintained for future extensibility, but
 * the 'remaining' calculation can underflow if len > remaining,
 * allowing memcpy outside the bounds of local_store[128].
 */
void parse_preferences(unsigned char *data, uint16_t data_len) {
    unsigned char local_store[128];
    uint16_t cursor    = 0;
    uint16_t remaining = data_len;
    while (remaining >= 2) {
        uint8_t type  = data[cursor++];
        uint8_t t_len = data[cursor++];
        remaining -= 2;                          /* ← underflow if remaining < 2 */
        if (t_len <= remaining) {
            if (type == 0xAA || type == 0xAB || type == 0xAC)
                memcpy(local_store, &data[cursor], t_len); /* ← BOF if t_len > 128 */
            cursor    += t_len;
            remaining -= t_len;
        } else break;
    }
}

/*
 * Clean TLV parser for clinical alert thresholds.
 *   Type 0xBB (4 bytes): bpm_min + bpm_max (uint16_t big-endian each)
 *   Type 0xCC (1 byte):  spo2_min
 * Writes result to THRESH_FILE for sensor service to consume.
 */
static void parse_thresholds(unsigned char *data, uint16_t data_len) {
    uint16_t bpm_min  = 50;   /* default clinical values */
    uint16_t bpm_max  = 120;
    uint8_t  spo2_min = 90;

    uint16_t cursor = 0;
    while (cursor + 2 <= data_len) {
        uint8_t type = data[cursor++];
        uint8_t tlen = data[cursor++];
        if (cursor + tlen > data_len) break;

        if (type == 0xBB && tlen == 4) {
            bpm_min = ((uint16_t)data[cursor]   << 8) | data[cursor+1];
            bpm_max = ((uint16_t)data[cursor+2] << 8) | data[cursor+3];
        } else if (type == 0xCC && tlen == 1) {
            spo2_min = data[cursor];
        }
        cursor += tlen;
    }

    int fd = open(THRESH_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf),
                         "bpm_min=%u\nbpm_max=%u\nspo2_min=%u\n",
                         bpm_min, bpm_max, spo2_min);
        write(fd, buf, n);
        close(fd);
    }
}

/* ── Diagnostic handlers ──────────────────────────────────────────────── */

/*
 * VULNERABILITY 3: Format String.
 * Real context: diagnostics for a named device subsystem.
 * Valid modules: "CareOtter", "BLE", "Sensor", "Network".
 *
 * The module name comes from the payload and is passed directly to snprintf
 * without a format specifier — if it contains '%x' it filters the stack, '%n' writes.
 */
void get_system_status(int c_fd, char *module_name) {
    struct sysinfo si;
    struct utsname un;
    char status_msg[512];
    char uptime_str[64];

    sysinfo(&si);
    uname(&un);

    long days  = si.uptime / 86400;
    long hours = (si.uptime / 3600) % 24;
    snprintf(uptime_str, sizeof(uptime_str), "%ldd %ldh", days, hours);

    /* VULNERABLE: module_name from payload as snprintf format */
    char report_header[128];
    snprintf(report_header, 128, module_name);  /* <── FORMAT STRING */

    snprintf(status_msg, sizeof(status_msg),
             "Status for [%s]\nUptime: %s\nLoad: %ld%%\nAuth: %s",
             report_header, uptime_str,
             si.loads[0] / 1000,
             authenticated ? "ADMIN" : "GUEST");

    send(c_fd, status_msg, strlen(status_msg), 0);
}

/* ── IGP command dispatcher ──────────────────────────────────────────── */

void handle_request(int c_fd) {
    igp_hdr_t hdr;
    if (recv(c_fd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) return;
    if (ntohl(hdr.magic) != MAGIC) return;

    uint16_t p_len = ntohs(hdr.len);
    unsigned char *payload = malloc(p_len + 1);
    if (!payload) return;
    if (p_len > 0) {
        recv(c_fd, payload, p_len, 0);
        payload[p_len] = '\0';
    }

    switch (hdr.cmd) {

        /* ── 0x01 SYS_INFO — public system information ─────────────── */
        case 0x01: {
            struct utsname s;
            uname(&s);
            char msg[128];
            snprintf(msg, sizeof(msg), "v:%s|m:%s", s.release, s.machine);
            send(c_fd, msg, strlen(msg), 0);
            log_event("SYS_INFO requested");
            break;
        }

        /* ── 0x02 AUTHENTICATE — admin token login ───────── */
        /* VULNERABILITY 1: hardcoded token visible with strings(1)         */
        case 0x02: {
            if (p_len > 0 &&
                strncmp((char*)payload, ADMIN_TOKEN, strlen(ADMIN_TOKEN)) == 0) {
                authenticated = 1;
                send(c_fd, "AUTH_SUCCESS", 12, 0);
                log_event("AUTHENTICATE: success");
            } else {
                send(c_fd, "AUTH_FAIL", 9, 0);
                log_event("AUTHENTICATE: fail");
            }
            break;
        }

        /* ── 0x03 GET_NETWORK — active network configuration ─────────────── */
        /* VULNERABILITY 2 (info disclosure): returns /etc/config/wireless  */
        /* including SSID and PSK in plaintext                               */
        case 0x03: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                log_event("GET_NETWORK: access denied");
                break;
            }
            int fd = open("/etc/config/wireless", O_RDONLY);
            if (fd < 0) {
                send(c_fd, "ERR_READ", 8, 0);
                break;
            }
            char config[512];
            int r = read(fd, config, sizeof(config));
            if (r > 0) send(c_fd, config, r, 0);
            close(fd);
            log_event("GET_NETWORK: config sent");
            break;
        }

        /* ── 0x04 SET_PREFS — app preferences (language/theme/screen) */
        /* VULNERABILITY 3: TLV parser with integer underflow in 'remaining'  */
        case 0x04: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }
            parse_preferences(payload, p_len);
            send(c_fd, "PREFS_SAVED", 11, 0);
            log_event("SET_PREFS: preferences updated");
            break;
        }

        /* ── 0x05 VERIFY_STATUS — named subsystem diagnostics ─────  */
        /* VULNERABILITY 4: format string in snprintf inside handler     */
        /* Valid modules: CareOtter / BLE / Sensor / Network               */
        case 0x05: {
            get_system_status(c_fd, (char*)payload);
            log_event("VERIFY_STATUS: diagnostic run");
            break;
        }

        /* ── 0x06 SET_WIFI — configures WiFi network via UCI ─────────────── */
        /* Payload: "SSID|PSK"                                                */
        /* FLAW: SSID and PSK interpolated in shell without escaping metacharacters */
        case 0x06: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }

            char *sep = strchr((char*)payload, '|');
            if (!sep || sep == (char*)payload) {
                send(c_fd, "ERR_FORMAT", 10, 0);
                break;
            }

            char ssid[64] = {0}, psk[64] = {0};
            size_t ssid_len = sep - (char*)payload;
            if (ssid_len >= sizeof(ssid)) {
                send(c_fd, "ERR_SSID_LEN", 12, 0);
                break;
            }
            strncpy(ssid, (char*)payload, ssid_len);
            strncpy(psk, sep + 1, sizeof(psk) - 1);

            if (strlen(psk) < 8) {
                send(c_fd, "ERR_PSK_SHORT", 13, 0);
                break;
            }

            /* FLAW: ssid and psk interpolated directly in shell command */
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "uci set wireless.@wifi-iface[0].ssid='%s' && "
                     "uci set wireless.@wifi-iface[0].key='%s' && "
                     "uci commit wireless && wifi reload",
                     ssid, psk);

            int r = system(cmd);
            if (r == 0) {
                send(c_fd, "WIFI_UPDATED", 12, 0);
                log_event("SET_WIFI: configuration applied");
            } else {
                send(c_fd, "WIFI_ERR", 8, 0);
                log_event("SET_WIFI: system() failed");
            }
            break;
        }

        /* ── 0x07 GET_VITALS — current BPM/SpO2 from sensor service ──── */
        /* Direct query to local medical service on port 8081           */
        case 0x07: {
            int v_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (v_fd < 0) {
                send(c_fd, "ERR_SOCKET", 10, 0);
                break;
            }

            struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
            setsockopt(v_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct sockaddr_in v_addr = {
                .sin_family      = AF_INET,
                .sin_port        = htons(SENSOR_PORT),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
            };

            if (connect(v_fd, (struct sockaddr*)&v_addr, sizeof(v_addr)) != 0) {
                close(v_fd);
                send(c_fd, "ERR_CONNECT", 11, 0);
                break;
            }

            const char *req = "GET /vitals HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
            write(v_fd, req, strlen(req));

            char resp[1024] = {0};
            int n = read(v_fd, resp, sizeof(resp) - 1);
            close(v_fd);

            if (n > 0) send(c_fd, resp, n, 0);
            else       send(c_fd, "ERR_EMPTY", 9, 0);
            break;
        }

        /* ── 0x08 SET_THRESHOLD — BPM and SpO2 alert thresholds ─────────── */
        /* TLV: Type 0xBB = bpm_min+bpm_max (4 bytes), Type 0xCC = spo2_min  */
        case 0x08: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }
            parse_thresholds(payload, p_len);
            send(c_fd, "THRESHOLD_SET", 13, 0);
            log_event("SET_THRESHOLD: thresholds updated");
            break;
        }

        /* ── 0x09 REBOOT_SERVICE — restarts init.d service ─────────────── */
        /* Payload: service name (e.g: "medical-sensor", "careservice") */
        /* FLAW: waitpid() omitted — child processes become zombies            */
        case 0x09: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }
            if (!is_valid_service_name((char*)payload)) {
                send(c_fd, "ERR_INVALID_NAME", 16, 0);
                break;
            }

            char svc_path[64];
            snprintf(svc_path, sizeof(svc_path), "/etc/init.d/%s", (char*)payload);

            char log_msg[80];
            snprintf(log_msg, sizeof(log_msg), "REBOOT_SERVICE: %s", (char*)payload);
            log_event(log_msg);

            pid_t pid = fork();
            if (pid == 0) {
                /* child: execute service restart */
                char *argv[] = { svc_path, "restart", NULL };
                execv(svc_path, argv);
                _exit(1);   /* execv only returns on failure */
            } else if (pid > 0) {
                /* FLAW: no waitpid() — zombie until parent terminates */
                send(c_fd, "SVC_RESTART_QUEUED", 18, 0);
            } else {
                send(c_fd, "REBOOT_ERR", 10, 0);
            }
            break;
        }

        /* ── 0x0A GET_LOG — last 512 bytes of service log ─────── */
        case 0x0A: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }
            int lfd = open(LOG_FILE, O_RDONLY);
            if (lfd < 0) {
                send(c_fd, "LOG_EMPTY", 9, 0);
                break;
            }
            off_t sz     = lseek(lfd, 0, SEEK_END);
            off_t offset = (sz > 512) ? sz - 512 : 0;
            lseek(lfd, offset, SEEK_SET);

            char logbuf[512];
            int n = read(lfd, logbuf, sizeof(logbuf));
            close(lfd);

            if (n > 0) send(c_fd, logbuf, n, 0);
            else       send(c_fd, "LOG_EMPTY", 9, 0);
            break;
        }

        /* ── 0x0B DEFIBRILLATE — simulates defibrillator discharge ────── */
        /* Requires auth. Logs event to EVENTS_FILE.                           */
        /* VULNERABILITY: log write uses sprintf with payload data — format    */
        /* string sink. Payload like "%x.%x.%x" leaks stack into events log.  */
        case 0x0B: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }

            int efd = open(EVENTS_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (efd >= 0) {
                time_t ts = time(NULL);
                char event_msg[256];
                char fmt_buf[128];
                /* VULNERABLE: payload used as snprintf format — second format string sink */
                snprintf(fmt_buf, sizeof(fmt_buf), (char*)payload);
                snprintf(event_msg, sizeof(event_msg),
                         "[%ld] DEFIB_TRIGGERED:200J context=%s\n", (long)ts, fmt_buf);
                write(efd, event_msg, strlen(event_msg));
                close(efd);
            }

            char resp[64];
            snprintf(resp, sizeof(resp), "DEFIB_TRIGGERED:200J:%ld", (long)time(NULL));
            send(c_fd, resp, strlen(resp), 0);
            log_event("DEFIBRILLATE: discharge simulated");
            break;
        }

        /* ── 0x0C EMERGENCY_ALERT — sends alert via curl ────────────────── */
        /* Requires auth. Reads endpoint URL from ALERT_CONF, calls curl with */
        /* the payload as message body via system().                           */
        /* VULNERABILITY: payload interpolated directly in shell command —     */
        /* OS command injection. Payload "test'; reboot #" triggers reboot.   */
        case 0x0C: {
            if (!authenticated) {
                send(c_fd, "RESTRICTED", 10, 0);
                break;
            }

            /* Read alert endpoint URL from config file */
            char url[256] = "http://127.0.0.1:8090/alert";  /* fallback */
            int cfd = open(ALERT_CONF, O_RDONLY);
            if (cfd >= 0) {
                char line[256] = {0};
                read(cfd, line, sizeof(line) - 1);
                close(cfd);
                /* Parse first line as URL */
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (strlen(line) > 0) strncpy(url, line, sizeof(url) - 1);
            }

            /* VULNERABLE: payload inserted directly into shell command */
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "curl -s -X POST '%s' -d 'msg=%s' > /dev/null 2>&1",
                     url, (char*)payload);
            system(cmd);  /* <── COMMAND INJECTION */

            char resp[128];
            snprintf(resp, sizeof(resp), "ALERT_SENT:%s", (char*)payload);
            send(c_fd, resp, strlen(resp), 0);
            log_event("EMERGENCY_ALERT: alert dispatched");
            break;
        }

        /* ── 0x0D DEAUTHENTICATE — closes the administrator session ───────── */
        /* Resets the global authenticated=0 flag. Call after each command    */
        /* to minimize the exposure window of the state.                      */
        /* NOTE: it does not eliminate the risk window between TCP connections */
        /* — it only reduces its duration.                                    */
        case 0x0D: {
            authenticated = 0;
            send(c_fd, "DEAUTH_OK", 9, 0);
            log_event("DEAUTHENTICATE: session closed");
            break;
        }

        default:
            send(c_fd, "ERR_CMD", 7, 0);
            break;
    }

    free(payload);
}

/* ── Main server ──────────────────────────────────────────────────── */

int main(void) {
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in s_addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(s_fd, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(s_fd, 5) < 0) {
        perror("listen"); return 1;
    }

    log_event("careservice started on port " STRINGIFY(PORT));

    while (1) {
        int c_fd = accept(s_fd, NULL, NULL);
        if (c_fd < 0) continue;
        handle_request(c_fd);
        close(c_fd);
    }
}
