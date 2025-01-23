#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <dlfcn.h>

// Prototype de la fonction originale
typedef int (*pam_authenticate_t)(pam_handle_t *, int);

// Interception de la fonction pam_authenticate
int pam_authenticate(pam_handle_t *pamh, int flags) {
    // Affichage pour indiquer que la fonction a été interceptée
    printf("Intercepted pam_authenticate call\n");

    // Chargement de la fonction originale
    pam_authenticate_t original_pam_authenticate = (pam_authenticate_t)dlsym(RTLD_NEXT, "pam_authenticate");

    if (!original_pam_authenticate) {
        fprintf(stderr, "Failed to locate original pam_authenticate: %s\n", dlerror());
        return PAM_SYSTEM_ERR;
    }

    // Si vous souhaitez injecter une réponse personnalisée, faites-le ici
    const char *fake_password = "fake_password";
    printf("Using fake password for testing: %s\n", fake_password);

    // Appeler la fonction originale si nécessaire
    int result = original_pam_authenticate(pamh, flags);

    // Affichage du résultat de la fonction originale
    printf("Original pam_authenticate returned: %d\n", result);

    // Retourner le résultat (ou modifiez-le selon vos besoins)
    return result;
}


