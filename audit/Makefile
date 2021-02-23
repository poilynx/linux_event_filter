 TARGET = notify_file notify_syscall notify_exec
LDFLAGS = -laudit
 CFLAGS = -g

all: $(TARGET)
%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)
clean:
	$(RM) $(TARGET) *.o

.PHONY: all clean

