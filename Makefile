CC = /usr/bin/gcc
CFLAGS = -Wall -Werror -g
LDFLAGS = -lcrypto -lssl

SUBJECT_BLOB=/C=IT/ST=Padova/L=Padova/O=Global Security/OU=IT Department/CN=
KEY_PATH=keys/

#Self signed root certificate authority
CA_KEY=$(KEY_PATH)ca_key.pem
CA_CERT=$(KEY_PATH)ca_cert.pem
CA_DOMAIN=localhost
CA_SUBJECT="$(SUBJECT_BLOB)$(CA_DOMAIN)"

#Server certificate and key
S_KEY=$(KEY_PATH)server_key.pem
S_CERT=$(KEY_PATH)server_cert.pem
S_DOMAIN=server.localhost
S_SUBJECT="$(SUBJECT_BLOB)$(S_DOMAIN)"

#Client certificate and key
C_KEY=$(KEY_PATH)client_key.pem
C_CERT=$(KEY_PATH)client_cert.pem
C_DOMAIN=client.localhost
C_SUBJECT="$(SUBJECT_BLOB)$(C_DOMAIN)"

CFLAGS=-g -ggdb

RSALEN=4096

all: build $(CA_KEY) $(CA_CERT) $(S_KEY) $(S_CERT) $(C_KEY) $(C_CERT) $(KEY_PATH)

build: client.h server.h
	$(CC) $(CFLAGS) -o openssl main.c client.c server.c $(LDFLAGS)

$(KEY_PATH):
	mkdir -p $(KEY_PATH)
	chmod 700 -R $(KEY_PATH)

$(CA_KEY): $(KEY_PATH)
	openssl genrsa -out $(CA_KEY) $(RSASTRENGTH)

$(CA_CERT): $(CA_KEY) $(KEY_PATH)
	openssl req -x509 -sha256 -new -nodes -key $(CA_KEY) -days 3650 -out $(CA_CERT) -subj $(CA_SUBJECT)

$(S_KEY): $(KEY_PATH)
	openssl genrsa -out $(S_KEY) $(RSASTRENGTH)

$(S_CERT): $(S_KEY) $(CA_CERT) $(KEY_PATH)
	# Create sign request
	openssl req -new -key $(S_KEY) -out $(KEY_PATH)s_signreq.csr -subj $(S_SUBJECT)
	# Validate it
	#openssl req -in s_signreq.csr -noout -text
	# Create server cert
	openssl x509 -req -in $(KEY_PATH)s_signreq.csr -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(S_CERT) -days 500 -sha256
	# Validate it
	#openssl x509 -in $(CA_CERT) -text -noout

$(C_KEY): $(KEY_PATH)
	openssl genrsa -out $(C_KEY) $(RSASTRENGTH)

$(C_CERT): $(C_KEY) $(CA_CERT) $(KEY_PATH)
		# Create sign request
	openssl req -new -key $(C_KEY) -out $(KEY_PATH)c_signreq.csr -subj $(C_SUBJECT)
	# Validate it
	#openssl req -in s_signreq.csr -noout -text
	# Create server cert
	openssl x509 -req -in $(KEY_PATH)c_signreq.csr -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(C_CERT) -days 500 -sha256
	# Validate it
	#openssl x509 -in $(CA_CERT) -text -noout


clean:
	rm -f *.o core openssl keys/*

start_server:
	./openssl server 8888 $(CA_CERT) $(S_CERT) $(S_KEY)

start_client:
	./openssl client localhost:8888 $(CA_CERT) $(C_CERT) $(C_KEY)