TARGET=main
CC=gcc

CFLAGS= -Wall -Wextra -g -O2

SRC= main.c

OBJ=$(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
    $(CC) $(CFLAGS) -o $@ $^


%.o: %.c
    $(CC) $(CFLAGS) -c $< -o $@


clean:
    rm -f $(OBJ) $(TARGET)

.PHONY: all clean
