CC=gcc
CFLAGS=-fPIC -Wall -Wextra
LDFLAGS=-ldl
OUTPUT_DIR=$(abspath ../checker/output/)
CFLAGS+=-DOUTPUT_TEMPLATE="\"$(OUTPUT_DIR)/out-XXXXXX\""
LDLIBS=$(abspath ./libipc.so)

build: outdir server client_inet

outdir:
	@mkdir -p $(OUTPUT_DIR)

server: server.o log.o libipc.so
	$(CC) -o $@ $^ $(LDLIBS) $(LDFLAGS)

client_inet: client_inet.o $(LDLIBS)

server.o: server.cpp server.h ipc.h
	$(CC) $(CFLAGS) -o $@ -c $<

libipc.so: ipc.o
	$(CC) -shared -o $@ $^

ipc.o: ipc.cpp ipc.h
	$(CC) $(CFLAGS) -o $@ -c $<

log.o: log.cpp log.h
	$(CC) $(CFLAGS) -o $@ -c $<

client_inet.o: client_inet.cpp
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -rf server *.o libipc.so client_inet
