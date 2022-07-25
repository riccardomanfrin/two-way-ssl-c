#include "sslsocket.h"
#include <openssl/bio.h>
#include "openssl_hostname_validation.h"

SSLSocket::SSLSocket(std::string _addr, uint16_t _port, std::string _ca_cert)
    : addr(_addr)
    , port(_port)
    , ca_cert(_ca_cert)
{

}

SSLSocket::SSLSocket(std::string _addr, uint16_t _port, std::string _ca_cert, std::string _client_cert, std::string _client_key) 
    : addr(_addr)
    , port(_port)
    , ca_cert(_ca_cert)
    , client_cert(_client_cert)
    , client_key(_client_key)
{
    
}
SSLSocket::~SSLSocket()
{
    if (sbio) {
        BIO_ssl_shutdown(sbio);
        BIO_free_all(sbio);
    }
    if (ctx) SSL_CTX_free(ctx);
}
int SSLSocket::connect() {
    X509 *server_cert;
    size_t len;
    /* Failure till we know it's a success */
    int rc = -1;
    const char *conn_str = std::string(addr + std::to_string(port)).c_str();

    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Get a context */
    if (!(ctx = get_client_context())) {
        return rc;
    }

    /* Get a BIO */
    if (!(sbio = BIO_new_ssl_connect(ctx))) {
        fprintf(stderr, "Could not get a BIO object from context\n");
        goto fail1;
    }

    /* Get the SSL handle from the BIO */
    BIO_get_ssl(sbio, &ssl);

    /* Connect to the server */
    if (BIO_set_conn_hostname(sbio, conn_str) != 1) {
        fprintf(stderr, "Could not connecto to the server\n");
        goto fail2;
    }

    /* Perform SSL handshake with the server */
    if (SSL_do_handshake(ssl) != 1) {
        fprintf(stderr, "SSL Handshake failed\n");
        goto fail2;
    }

    /* Verify that SSL handshake completed successfully */
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Verification of handshake failed\n");
        goto fail2;
    }

    server_cert =  SSL_get_peer_certificate(ssl);
    if (server_cert == NULL) {
        // The handshake was successful although the server did not provide a certificate
        // Most likely using an insecure anonymous cipher suite... get out!
        fprintf(stderr, "Failed to retrieve server certificate\n");
        goto fail2;
    }

    
    // Validate the hostname
    if (validate_hostname(addr.c_str(), server_cert) != MatchFound) {
        fprintf(stderr, "Hostname validation failed.\n");
        goto fail2;
    }


    /* Inform the user that we've successfully connected */
    printf("SSL handshake successful with %s\n", conn_str);

    return (0);

fail3:
    BIO_ssl_shutdown(sbio);
fail2:
    BIO_free_all(sbio);
fail1:
    SSL_CTX_free(ctx);
    return rc;
}

int SSLSocket::send(uint8_t *data, uint32_t len) {
    int rc = 0;
    if ((rc = SSL_write(ssl, (const char *) data, (int) len)) != len) {
        fprintf(stderr, "Cannot write to the server\n");
    }
    return rc;
}
int SSLSocket::recv(uint8_t *&data, uint32_t &len) {
    int rc = 0;
    if ((rc = SSL_read(ssl, data, len)) < 0) {
        fprintf(stderr, "Cannot read from the server\n");
    }
    len = (uint32_t) rc;
    return rc;
}

SSL_CTX *SSLSocket::get_client_context() {
    SSL_CTX *ctx;

    /* Create a generic context */
    if (!(ctx = SSL_CTX_new(SSLv23_client_method()))) {
        fprintf(stderr, "Cannot create a client context\n");
        return NULL;
    }

    /* Load the client's CA file location */
    if (SSL_CTX_load_verify_locations(ctx, ca_cert.c_str(), NULL) != 1) {
        fprintf(stderr, "Cannot load client's CA file\n");
        goto fail;
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, client_cert.c_str(), SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Cannot load client's certificate file\n");
        goto fail;
    }

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key.c_str(), SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Cannot load client's key file\n");
        goto fail;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Client's certificate and key don't match\n");
        goto fail;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    /* Done, return the context */
    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}