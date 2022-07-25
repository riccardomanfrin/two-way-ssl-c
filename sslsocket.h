#ifndef __SSLSocket_h__
#define __SSLSocket_h__

#include <stdlib.h>
#include <openssl/ssl.h>
#include <string>

class SSLSocket {
public:
    SSLSocket(std::string addr, uint16_t port, std::string ca_cert);
    SSLSocket(std::string addr, uint16_t port, std::string ca_cert, std::string client_cert, std::string client_key);
    ~SSLSocket();
    int connect();
    int send(uint8_t *data, uint32_t len);
    int recv(uint8_t *&data, uint32_t &len);

private:
    //Config
    std::string addr;
    uint16_t port;
    std::string ca_cert;
    std::string client_cert;
    std::string client_key;
    //SSL specific
    SSL *ssl;
    SSL_CTX *ctx;
    BIO *sbio;

private:
    SSL_CTX *get_client_context();
};

#endif