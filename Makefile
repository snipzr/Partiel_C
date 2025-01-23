# Nom de la bibliothèque
TARGET=libpam_auth_logger.so

# Options du compilateur
CFLAGS=-Wall -Wextra -g -O2 -fPIC
LDFLAGS=-shared -ldl

# Fichiers sources
SRC=pam_auth_logger.c

# Compilation
all:
	gcc $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

