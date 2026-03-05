#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *allowed_cmds[] = {
    "echo", "pwd", "ls", "cd", "whoami", "id", "uname", "uptime", "df", "free",
    "ifconfig", "ping", "traceroute", "find", "cat", "awk", "more", "less", "head", "tail",
    "file", "grep", "wc", "sort", "uniq", "clear", "date", "touch", "mkdir", "su"
};

const char *help_list[] = {
  "help      - Show this help message\n",
  "echo      - Displays a line of text\n",
  "pwd       - Print name of current/working directory\n",
  "whoami    - Print effective user name\n",
  "ls        - List directory contents\n",
  "cd        - Change the current directory\n",
  "id        - Print user and group information\n",
  "uname     - Print system information\n",
  "uptime    - Show how long the system has been running\n",
  "df        - Report file system disk space usage\n",
  "free      - Display memory usage\n",
  "ifconfig  - Configure/display network interfaces\n",
  "ping      - Send ICMP ECHO_REQUEST to network hosts\n",
  "traceroute- Trace the route to a network host\n",
  "find      - Search for files in a directory hierarchy\n",
  "cat       - Concatenate and display files\n",
  "awk       - View file content with backward/forward navigation\n",
  "more      - View file content page by page\n",
  "less      - View file content with backward/forward navigation\n",
  "head      - Output the first part of files\n",
  "tail      - Output the last part of files\n",
  "file      - Determine file type\n",
  "grep      - Search for patterns in files\n",
  "wc        - Count lines, words, and bytes\n",
  "sort      - Sort lines of text files\n",
  "uniq      - Report or omit repeated lines\n",
  "clear     - Clear the terminal screen\n",
  "date      - Display or set the system date and time\n",
  "touch     - Change file timestamps or create empty files\n",
  "mkdir     - Create new directories\n",
  "su        - Switch user (upgrade to root in order to perform administrative tasks)\n",
  "exit      - Terminate session\n"
};

int is_allowed(const char *cmd) {
    char main_cmd[32];
    if (sscanf(cmd, "%31s", main_cmd) != 1) return 0;
    size_t num_cmds = sizeof(allowed_cmds) / sizeof(allowed_cmds[0]);
    for (size_t i = 0; i < num_cmds; i++) {
        if (strcmp(main_cmd, allowed_cmds[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void print_help() {
    printf("Allowed commands:\n");
    size_t num_cmds = sizeof(help_list) / sizeof(help_list[0]);
    for (size_t i = 0; i < num_cmds; i++) {
        printf("  %s", help_list[i]);
    }
}

int is_echo_safe(const char *cmd) {
    const char *p = cmd + 4;
    while (*p) {
        if (strchr("$`|><;&*?()[]{}", *p)) {
            return 0;
        }
        p++;
    }
    return 1;
}

int main() {
    char cmd[256];
    system("cat /etc/restricted_banner");
    while (1) {
        printf("rshell> ");
        fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        cmd[strcspn(cmd, "\n")] = 0;

        if (strcmp(cmd, "") == 0) {
            continue;
        }

        if (strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "help") == 0) {
            print_help();
        } else if (strncmp(cmd, "cd", 2) == 0) {
            char *path = cmd + 3;
            if (chdir(path) != 0) {
                perror("cd failed");
            }
        } else if (strncmp(cmd, "echo", 4) == 0) {
            if (is_echo_safe(cmd)) {
                system(cmd);
            } else {
                printf("Unsafe 'echo' characters restriction.\n");
            }
        } else if (is_allowed(cmd)) {
            system(cmd);
        } else {
            printf("Command not allowed nor found.\n");
        }
    }
    return 0;
}
