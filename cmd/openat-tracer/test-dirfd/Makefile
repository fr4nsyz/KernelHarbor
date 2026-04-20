CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
TARGET   = test-dirfd

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
