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
    int listen();
    int const send(const uint8_t *data, uint32_t len);
    int recv(uint8_t *data, uint32_t &len);

private:
    int validate_hostname(const char *hostname);

private:
    //Config
    std::string addr;
    uint16_t port;
    std::string ca_cert;
    std::string client_cert;
    std::string client_key;
    //SSL specific
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    BIO *sbio = NULL;
};

#endif