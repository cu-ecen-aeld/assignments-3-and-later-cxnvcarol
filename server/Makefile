CC :=$(if $(CROSS_COMPILE),$(CROSS_COMPILE)gcc,$(CC))
CCFLAGS=-g -Wall -Werror
TARGET ?=aesdsocket
LDFLAGS ?= -lpthread -lrt
all: $(TARGET).c
	$(CC) $(CCFLAGS) $(TARGET).c -o $(TARGET) $(LDFLAGS)
clean:
	rm -f $(TARGET)
