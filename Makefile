# Nom de la bibliothèque
TARGET = libpam_auth_logger.so

# Options du compilateur
CFLAGS  = -Wall -Wextra -g -O2 -fPIC
LDFLAGS = -shared -ldl

# Fichiers sources : pam_auth_logger.c + block_files.c
SRC = pam_auth_logger.c block_files.c

# Compilateur
CC = gcc

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

