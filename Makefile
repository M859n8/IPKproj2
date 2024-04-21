CC = g++
CFLAGS = -std=c++11 -Wall
SRCS = ipk-sniffer.cpp Arguments.cpp
EXEC = ipk-sniffer

all: $(EXEC)

$(EXEC): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -lpcap -o $(EXEC)
run: 
	sudo ./ipk-sniffer -i eth0 -n 15
clean:
	rm -f $(EXEC)


