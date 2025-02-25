CC :=$(if $(CROSS_COMPILE),$(CROSS_COMPILE)gcc,$(CC))
CCFLAGS=-g -Wall -Werror
all: aesdsocket.c
	$(CC) $(CCFLAGS) aesdsocket.c -o aesdsocket
clean:
	rm -f aesdsocket
