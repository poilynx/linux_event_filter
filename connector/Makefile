    CC = cc
CFLAGS = -g
  OBJS = notify_event.o
TARGET = notify_event

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(CFLAGS)

clean:
	$(RM) $(TARGET) $(OBJS)
