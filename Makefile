CC = g++
CFLAGS = -std=c++11 -Wall
SRCS = ipk-sniffer.cpp Arguments.cpp
EXEC = ipk-sniffer

all: $(EXEC)

$(EXEC): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -lpcap -o $(EXEC)

clean:
	rm -f $(EXEC)


