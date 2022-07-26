#include "sslsocket.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <string.h>

static SSL_CTX *get_client_context(std::string &ca_cert, std::string &client_cert, std::string &client_key);

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
    const char *conn_str = std::string(addr + ":" + std::to_string(port)).c_str();

    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Get a context */
    if (!(ctx = get_client_context(ca_cert, client_cert, client_key))) {
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

    // Validate the hostname
    if (validate_hostname(addr.c_str()) != 0) {
        fprintf(stderr, "Hostname validation failed.\n");
        goto fail2;
    }


    /* Inform the user that we've successfully connected */
    fprintf(stderr, "SSL handshake successful with %s\n", conn_str);

    return (0);

fail3:
    BIO_ssl_shutdown(sbio);
fail2:
    BIO_free_all(sbio);
fail1:
    SSL_CTX_free(ctx);
    return rc;
}

int const SSLSocket::send(const uint8_t *data, uint32_t len) {
    int rc = 0;
    if ((rc = SSL_write(ssl, (const char *) data, (int) len)) != len) {
        fprintf(stderr, "Cannot write to the server\n");
    }
    return rc;
}
int SSLSocket::recv(uint8_t *data, uint32_t &len) {
    int rc = 0;
    if ((rc = SSL_read(ssl, data, len)) < 0) {
        fprintf(stderr, "Cannot read from the server\n");
    }
    len = (uint32_t) rc;
    return rc;
}

static SSL_CTX *get_client_context(std::string &ca_cert, std::string &client_cert, std::string &client_key) {
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

typedef enum {
    MatchFound,
    MatchNotFound,
    NoSANPresent,
    MalformedCertificate,
    Error
} HostnameValidationResult;

#define HOSTNAME_MAX_SIZE 255

/**
* Tries to find a match for hostname in the certificate's Common Name field.
*
* Returns MatchFound if a match was found.
* Returns MatchNotFound if no matches were found.
* Returns MalformedCertificate if the Common Name had a NUL character embedded in it.
* Returns Error if the Common Name could not be extracted.
*/
static HostnameValidationResult matches_common_name(const char *hostname, const X509 *server_cert) {
	int common_name_loc = -1;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
	char *common_name_str = NULL;

	// Find the position of the CN field in the Subject field of the certificate
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) server_cert), NID_commonName, -1);
	if (common_name_loc < 0) {
		return Error;
	}

	// Extract the CN field
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) server_cert), common_name_loc);
	if (common_name_entry == NULL) {
		return Error;
	}

	// Convert the CN field to a C string
	common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
		return Error;
	}			
	common_name_str = (char *) ASN1_STRING_get0_data(common_name_asn1);

	// Make sure there isn't an embedded NUL character in the CN
	if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
		return MalformedCertificate;
	}

	// Compare expected hostname with the CN
	if (strcasecmp(hostname, common_name_str) == 0) {
		return MatchFound;
	}
	else {
		return MatchNotFound;
	}
}

/**
* Tries to find a match for hostname in the certificate's Subject Alternative Name extension.
*
* Returns MatchFound if a match was found.
* Returns MatchNotFound if no matches were found.
* Returns MalformedCertificate if any of the hostnames had a NUL character embedded in it.
* Returns NoSANPresent if the SAN extension was not present in the certificate.
*/
static HostnameValidationResult matches_subject_alternative_name(const char *hostname, const X509 *server_cert) {
	HostnameValidationResult result = MatchNotFound;
	int i;
	int san_names_nb = -1;
	STACK_OF(GENERAL_NAME) *san_names = NULL;

	// Try to extract the names within the SAN extension from the certificate
	san_names = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i((X509 *) server_cert, NID_subject_alt_name, NULL, NULL);
	if (san_names == NULL) {
		return NoSANPresent;
	}
	san_names_nb = sk_GENERAL_NAME_num(san_names);

	// Check each name within the extension
	for (i=0; i<san_names_nb; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

		if (current_name->type == GEN_DNS) {
			// Current name is a DNS name, let's check it
			char *dns_name = (char *) ASN1_STRING_get0_data(current_name->d.dNSName);

			// Make sure there isn't an embedded NUL character in the DNS name
			if (ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
				result = MalformedCertificate;
				break;
			}
			else { // Compare expected hostname with the DNS name
				if (strcasecmp(hostname, dns_name) == 0) {
					result = MatchFound;
					break;
				}
			}
		}
	}
	sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

	return result;
}


/**
* Validates the server's identity by looking for the expected hostname in the
* server's certificate. As described in RFC 6125, it first tries to find a match
* in the Subject Alternative Name extension. If the extension is not present in
* the certificate, it checks the Common Name instead.
*
* Returns MatchFound if a match was found.
* Returns MatchNotFound if no matches were found.
* Returns MalformedCertificate if any of the hostnames had a NUL character embedded in it.
* Returns Error if there was an error.
*/
int SSLSocket::validate_hostname(const char *hostname) {
    const X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert == NULL) {
        // The handshake was successful although the server did not provide a certificate
        // Most likely using an insecure anonymous cipher suite... get out!
        fprintf(stderr, "Failed to retrieve server certificate\n");
        return -1;
    }

	HostnameValidationResult result;

	if((hostname == NULL)) {
        fprintf(stderr, "Hostname unspecified\n");
        return -1;
    }

	// First try the Subject Alternative Names extension
	result = matches_subject_alternative_name(hostname, server_cert);
	if (result == NoSANPresent) {
		// Extension was not found: try the Common Name
		result = matches_common_name(hostname, server_cert);
	}

	return result != MatchFound;
}