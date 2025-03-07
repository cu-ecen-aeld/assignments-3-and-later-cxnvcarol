CC :=$(if $(CROSS_COMPILE),$(CROSS_COMPILE)gcc,$(CC))
CCFLAGS=-g -Wall -Werror
TARGET ?=aesdsocket
all: $(TARGET).c
	$(CC) $(CCFLAGS) $(TARGET).c -o $(TARGET)
clean:
	rm -f $(TARGET)
