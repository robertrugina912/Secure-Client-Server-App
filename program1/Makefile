.PHONY: all clean

CFLAGS=-g -DNDEBUG -fno-stack-protector
#export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
#export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"
#LDFLAGS=-g -z execstack
LDLIBS=-lsqlite3 -lcrypto -lssl -lm

all: client server serverkeys

clean:
	rm -f server client *.o chat.db
	if [ -d clientkeys ]; then rm -dr serverkeys; fi
	if [ -d clientkeys ]; then rm -dr ttpkeys; fi
	if [ -d clientkeys ]; then rm -dr clientkeys; fi

ui.o: ui.c ui.h

ssl.o: ssl.c ssl.h

client.o: client.c api.h ui.h util.h ssl.h

api.o: api.c api.h 

server.o: server.c util.h ssl.h

util.o: util.c util.h

worker.o: worker.c util.h worker.h

db.o: db.c util.h db.h

client: client.o api.o ui.o util.o db.o ssl.o

server: server.o api.o util.o worker.o db.o ssl.o

serverkeys:
	mkdir serverkeys
	mkdir ttpkeys
	mkdir clientkeys
	touch ./serverkeys/server-key.pem
	openssl genrsa -out ./serverkeys/server-key.pem 2> /dev/null
	touch ./serverkeys/ca-key.pem
	openssl genrsa -out ./serverkeys/ca-key.pem 2> /dev/null
	touch ./ttpkeys/ca-cert.pem
	openssl req -new -x509 -key ./serverkeys/ca-key.pem -out ./ttpkeys/ca-cert.pem -nodes -subj '/CN=ca\.localhost/'
	touch ./serverkeys/server-csr.pem
	openssl req -new -key ./serverkeys/server-key.pem -out ./serverkeys/server-csr.pem -nodes -subj '/CN=server\.localhost/'
	touch ./serverkeys/server-ca-cert.pem
	openssl x509 -req -CA ./ttpkeys/ca-cert.pem -CAkey ./serverkeys/ca-key.pem -CAcreateserial -in ./serverkeys/server-csr.pem -out ./serverkeys/server-ca-cert.pem 2> /dev/null