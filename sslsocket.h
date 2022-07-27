#ifndef __Socket_h__
#define __Socket_h__

#include <stdlib.h>
#include <openssl/ssl.h>
#include <string>

namespace Ssl
{

class Socket
{
public:
	Socket(std::string addr, uint16_t port, std::string ca_cert);
	Socket(std::string addr, uint16_t port, std::string ca_cert,
			std::string client_cert, std::string client_key);
	~Socket();
	int close();
	int connect();
	int listen();
	const Socket *accept();
	int send(const uint8_t *data, uint32_t len) const;
	int recv(uint8_t *data, uint32_t &len) const;

private:
	Socket(SSL *accepted_ssl, SSL_CTX *accepted_ctx);
	int validate_hostname(const char *hostname);

private:
	int listen_fd = -1;
	// Config
	std::string addr;
	uint16_t port;
	std::string ca;
	std::string cert;
	std::string key;
	// SSL specific
	SSL *ssl = NULL;
	SSL_CTX *ctx = NULL;
	BIO *sbio = NULL;
};

}; // namespace Ssl

#endif