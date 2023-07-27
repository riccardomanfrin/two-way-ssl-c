#https://stackoverflow.com/questions/2043617/is-it-possible-to-have-ssl-certificate-for-ip-address-not-domain-name
#The short answer is yes, as long as it is a public IP address.
#Issuance of certificates to reserved IP addresses is not allowed, 
#and all certificates previously issued to reserved IP addresses were 
#revoked as of 1 October 2016.
#According to the CA Browser forum, there may be compatibility issues with 
#certificates for IP addresses unless the IP address is in both the commonName and 
#subjectAltName fields. This is due to legacy SSL implementations which are not 
#aligned with RFC 5280, notably, Windows OS prior to Windows 10.

CC = /usr/bin/g++
CFLAGS = -Wall -Werror -g
LDFLAGS = -lcrypto -lssl -lresolv
USERID="anythinggoes"
NEID="AthonetNEIdentifier"
SUBJECT_BLOB=/C=IT/ST=Italy/L=Bolzano Vicentino/O=Global Security/OU=IT Department/CN=
KEY_PATH=keys/

#Self signed root certificate authority
CA_KEY=$(KEY_PATH)ca_key.pem
CA_CERT=$(KEY_PATH)ca_cert.pem
CA_DOMAIN="athonet.com"
CA_SUBJECT="$(SUBJECT_BLOB)$(CA_DOMAIN)"

#Server certificate and key 
#IP=172.21.5.65
#IP=127.0.0.1
IP=localhost
S_KEY=$(KEY_PATH)server_key.pem
S_SREQ=$(KEY_PATH)s_signreq.csr
S_CERT=$(KEY_PATH)server_cert.pem
S_DOMAIN="$(IP)"
S_SUBJECT="$(SUBJECT_BLOB)$(S_DOMAIN)/UID=$(NEID)"
#S_ALTNAME="-addext subjectAltName=IP:$(IP)"
#Client certificate and key
C_KEY=$(KEY_PATH)client_key.pem
C_SREQ=$(KEY_PATH)c_signreq.csr
C_CERT=$(KEY_PATH)client_cert.pem
C_DOMAIN="192.168.178.101"
C_SUBJECT="$(SUBJECT_BLOB)$(C_DOMAIN)/UID=$(USERID)"
P12=$(KEY_PATH)client.p12
P12PASS=foo
S_CERT_EXT=$(KEY_PATH)openssl.cnf

CFLAGS=-g -ggdb

RSALEN=4096

all: x1x2 build $(CA_KEY) $(CA_CERT) $(S_KEY) $(S_CERT) $(C_KEY) $(C_CERT) $(KEY_PATH) $(P12) $(S_SREQ) $(C_SREQ)

build: client.h server.h
	$(CC) $(CFLAGS) -o openssl main.cpp sslsocket.cpp client.cpp server.cpp $(LDFLAGS)

x1x2: $(CA_KEY) $(CA_CERT) $(S_KEY) $(S_CERT) $(C_KEY) $(C_CERT) $(KEY_PATH) $(P12) 
	./x1x2.sh

$(KEY_PATH):
	mkdir -p $(KEY_PATH)
	chmod 700 -R $(KEY_PATH)

$(P12): $(C_CERT) $(C_KEY) $(CA_CERT)
	openssl pkcs12 -export -out $(P12) -inkey $(C_KEY) -in $(C_CERT) -certfile $(CA_CERT) -passout pass:$(P12PASS)

$(S_CERT_EXT): $(KEY_PATH)
	echo "[ usr_cert ]\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer" > $(S_CERT_EXT)

$(CA_KEY): $(KEY_PATH)
	openssl genrsa -out $(CA_KEY) $(RSASTRENGTH)

$(CA_CERT): $(CA_KEY) $(KEY_PATH)
	openssl req -x509 -sha256 -new -nodes -key $(CA_KEY) -days 3650 -out $(CA_CERT) -subj $(CA_SUBJECT)

$(S_KEY): $(KEY_PATH)
	openssl genrsa -out $(S_KEY) $(RSASTRENGTH)

$(S_SREQ): $(S_KEY)
	# Create sign request
	openssl req -new -key $(S_KEY) -out $(S_SREQ) -subj $(S_SUBJECT) $(S_ALTNAME)

$(S_CERT): $(S_KEY) $(CA_CERT) $(KEY_PATH) $(S_CERT_EXT) $(S_SREQ)
	# Validate it
	#openssl req -in s_signreq.csr -noout -text
	# Create server cert
	openssl x509 -req -in $(S_SREQ) -extensions usr_cert -extfile $(S_CERT_EXT) -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(S_CERT) -days 3650 -sha256
	# Validate it
	#openssl x509 -in $(S_CERT) -text -noout

$(C_KEY): $(KEY_PATH)
	openssl genrsa -out $(C_KEY) $(RSASTRENGTH)

$(C_SREQ): $(C_KEY)
	# Create sign request
	openssl req -new -key $(C_KEY) -out $(S_SREQ) -subj $(S_SUBJECT) $(S_ALTNAME)

$(C_CERT): $(C_KEY) $(CA_CERT) $(KEY_PATH) $(C_SREQ)
	# Create sign request
	openssl req -new -key $(C_KEY) -out $(C_SREQ) -subj $(C_SUBJECT)
	# Validate it
	#openssl req -in s_signreq.csr -noout -text
	# Create server cert
	openssl x509 -req -in $(C_SREQ) -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(C_CERT) -days 500 -sha256
	# Validate it
	#openssl x509 -in $(CA_CERT) -text -noout

show:
	# Demonstrate the UID
	openssl x509 -in $(C_CERT) -text -noout -nameopt oid

clean:
	rm -f *.o core openssl $(S_KEY) $(S_SREQ) $(S_CERT) $(C_KEY) $(C_SREQ) $(C_CERT) $(S_CERT_EXT) $(P12) $(CA_KEY) $(CA_CERT) $(KEY_PATH)/x1_* $(KEY_PATH)/x2_*

clean_ca:
	rm -f $(CA_KEY) $(CA_CERT) 

start_server:
	./openssl server 127.0.0.1:8888 $(CA_CERT) $(S_CERT) $(S_KEY)

start_client:
	./openssl client 127.0.0.1:8888 $(CA_CERT) $(C_CERT) $(C_KEY)


.PHONY: x1x2