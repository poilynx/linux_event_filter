    CC = cc
CFLAGS = -g
  OBJS = trace.o
TARGET = trace

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(CFLAGS)

clean:
	$(RM) $(TARGET) $(OBJS)
