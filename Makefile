# Nom de la bibliothèque
TARGET=libpam_auth_v2.so

# Options du compilateur
CFLAGS=-Wall -Wextra -g -O2 -fPIC
LDFLAGS=-shared -ldl

# Fichiers sources
SRC=pam_auth_v2.c

# Compilation
all:
	gcc $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

