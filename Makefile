CC = /usr/bin/gcc
CFLAGS = -Wall -Werror -g
LDFLAGS = -lcrypto -lssl

SUBJECT_BLOB=/C=IT/ST=Padova/L=Padova/O=Global Security/OU=IT Department/CN=

#Self signed root certificate authority
CA_KEY=ca_key.pem
CA_CERT=ca_cert.pem
CA_DOMAIN=localhost
CA_SUBJECT="$(SUBJECT_BLOB)$(CA_DOMAIN)"

#Server certificate and key
S_KEY=server_key.pem
S_CERT=server_cert.pem
S_DOMAIN=localhost
S_SUBJECT="$(SUBJECT_BLOB)$(S_DOMAIN)"

#Client certificate and key
C_KEY=client_key.pem
C_CERT=client_cert.pem
C_DOMAIN=localhost
C_SUBJECT="$(SUBJECT_BLOB)$(C_DOMAIN)"


all: build $(CA_CERT) $(S_KEY) $(S_CERT) $(C_KEY) $(C_CERT) 

build: client.h server.h
	$(CC) $(CFLAGS) -o openssl main.c client.c server.c $(LDFLAGS)

$(CA_CERT):
	openssl req \
	    -x509 \
	    -nodes \
	    -days 3650 \
	    -newkey rsa:4096 \
	    -keyout $(CA_KEY) \
	    -out $(CA_CERT) \
	    -subj $(CA_SUBJECT)

$(S_KEY):
	openssl genrsa -out $(S_KEY) 4096

$(S_CERT): $(S_KEY) $(CA_CERT)
	# Create sign request
	openssl req -new -key $(S_KEY) -out s_signreq.csr -subj $(S_SUBJECT)
	# Validate it
	#openssl req -in s_signreq.csr -noout -text
	# Create server cert
	openssl x509 -req -in s_signreq.csr -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(S_CERT) -days 500 -sha256
	# Validate it
	#openssl x509 -in $(CA_CERT) -text -noout

$(C_KEY):
	openssl genrsa -out $(C_KEY) 4096

$(C_CERT): $(C_KEY) $(CA_CERT)
		# Create sign request
	openssl req -new -key $(C_KEY) -out s_signreq.csr -subj $(C_SUBJECT)
	# Validate it
	#openssl req -in s_signreq.csr -noout -text
	# Create server cert
	openssl x509 -req -in s_signreq.csr -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(C_CERT) -days 500 -sha256
	# Validate it
	#openssl x509 -in $(CA_CERT) -text -noout


clean:
	rm -f *.o core openssl *.pem *.csr
