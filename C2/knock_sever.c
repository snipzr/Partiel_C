#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define KNOCK_PORT1 5001
#define KNOCK_PORT2 5002
#define KNOCK_PORT3 5003
#define FINAL_PORT  4444
#define BUFFER_SIZE 1024

// État de la progression de knocks (0->1->2->3)
static int knockStep = 0;
// IP autorisée
static char expectedIP[INET_ADDRSTRLEN] = {0};
// Mutex
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// -----------------------------------
// Thread : écoute d’un port de knock
// -----------------------------------
void *knock_listener(void *arg) {
    int port = *(int*)arg;
    free(arg);

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Création socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        pthread_exit(NULL);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        pthread_exit(NULL);
    }

    printf("[Knock Listener] Listening on port %d...\n", port);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("[Knock Listener] Connection from %s on port %d\n", client_ip, port);

        pthread_mutex_lock(&lock);

        if (knockStep == 0 && port == KNOCK_PORT1) {
            knockStep = 1;
            strncpy(expectedIP, client_ip, INET_ADDRSTRLEN - 1);
            printf("[Knock Listener] Knock 1/3 réussi. IP: %s\n", client_ip);

        } else if (knockStep == 1 && port == KNOCK_PORT2) {
            if (strcmp(client_ip, expectedIP) == 0) {
                knockStep = 2;
                printf("[Knock Listener] Knock 2/3 réussi. IP: %s\n", client_ip);
            } else {
                knockStep = 0;
                printf("[Knock Listener] Mauvaise IP => reset.\n");
            }

        } else if (knockStep == 2 && port == KNOCK_PORT3) {
            if (strcmp(client_ip, expectedIP) == 0) {
                knockStep = 3;
                printf("[Knock Listener] Knock 3/3 réussi. Séquence validée!\n");
            } else {
                knockStep = 0;
                printf("[Knock Listener] Mauvaise IP => reset.\n");
            }
        } else {
            knockStep = 0;
            printf("[Knock Listener] Mauvaise séquence => reset.\n");
        }

        pthread_mutex_unlock(&lock);

        close(client_fd);
    }

    close(server_fd);
    pthread_exit(NULL);
}

// -----------------------------------
// Thread : serveur sur port 4444 (FINAL_PORT)
// pour recevoir le fichier credentials
// -----------------------------------
void *start_credentials_server(void *arg) {
    (void)arg;

    // Attendre que knockStep == 3
    while (1) {
        pthread_mutex_lock(&lock);
        int step = knockStep;
        pthread_mutex_unlock(&lock);

        if (step == 3) {
            break;
        }
        sleep(1);
    }

    printf("[Credentials Server] Séquence validée, on ouvre le port %d...\n", FINAL_PORT);

    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("[Credentials Server] socket");
        pthread_exit(NULL);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(FINAL_PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[Credentials Server] bind");
        close(server_sock);
        pthread_exit(NULL);
    }

    if (listen(server_sock, 1) < 0) {
        perror("[Credentials Server] listen");
        close(server_sock);
        pthread_exit(NULL);
    }

    printf("[Credentials Server] En écoute sur le port %d...\n", FINAL_PORT);

    client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("[Credentials Server] accept");
        close(server_sock);
        pthread_exit(NULL);
    }

    char *client_ip = inet_ntoa(client_addr.sin_addr);
    printf("[Credentials Server] Connexion acceptée depuis %s\n", client_ip);

    char filename[128];
    snprintf(filename, sizeof(filename), "credentials_%s.txt", client_ip);

    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("[Credentials Server] fopen");
        close(client_sock);
        close(server_sock);
        pthread_exit(NULL);
    }
    printf("[Credentials Server] Sauvegarde dans : %s\n", filename);

    ssize_t bytes_received;
    while ((bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        fwrite(buffer, 1, bytes_received, f);
    }
    fclose(f);

    if (bytes_received < 0) {
        perror("[Credentials Server] recv");
    } else {
        printf("[Credentials Server] Fichier %s reçu.\n", filename);
    }

    close(client_sock);
    close(server_sock);
    pthread_exit(NULL);
}

int main() {
    pthread_t t1, t2, t3, t_creds;

    int *p1 = malloc(sizeof(int)); *p1 = KNOCK_PORT1;
    int *p2 = malloc(sizeof(int)); *p2 = KNOCK_PORT2;
    int *p3 = malloc(sizeof(int)); *p3 = KNOCK_PORT3;

    // Lancement des 3 threads knocks
    pthread_create(&t1, NULL, knock_listener, p1);
    pthread_create(&t2, NULL, knock_listener, p2);
    pthread_create(&t3, NULL, knock_listener, p3);

    // Thread pour la réception credentials (port 4444)
    pthread_create(&t_creds, NULL, start_credentials_server, NULL);

    // On attend la fin du thread "credentials"
    pthread_join(t_creds, NULL);

    // On arrête les threads knocks
    pthread_cancel(t1);
    pthread_cancel(t2);
    pthread_cancel(t3);

    printf("[Main] Fermeture du programme.\n");
    return 0;
}

