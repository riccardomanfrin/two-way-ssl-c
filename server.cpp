/*
 *  server.c
 *  OpenSSL
 *
 *  Created by Thirumal Venkat on 18/05/16.
 *  Copyright © 2016 Thirumal Venkat. All rights reserved.
 */


#include <string>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "sslsocket.h"

/* Global variable that indicates work is present */
static int do_work = 1;

/* Buffer size to be used for transfers */
#define BUFSIZE 1000

static int get_host_port(const char *conn_str, std::string &addr , uint16_t &port) {
    char buff[BUFSIZE];
    strcpy(buff, conn_str);
    addr = std::string(strtok(buff, ":"));
    port = (uint16_t) atoi(strtok(NULL, ":"));
    return 0;
}

static int
proxy_to_clear_conn(const std::string &addr, int port_num, int &csock, int &accepted_fd)
{
	struct sockaddr_in sin;
	int sock, val;
    struct sockaddr_in csin;
	socklen_t csin_len;
	/* Create a socket */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Cannot create a socket\n");
		return (-1);
	}

	/* We don't want bind() to fail with EBUSY */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		fprintf(stderr, "Could not set SO_REUSEADDR on the socket\n");
		goto fail;
	}

	/* Fill up the server's socket structure */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	// sin.sin_addr.s_addr = INADDR_ANY;
	inet_net_pton(AF_INET,
			addr.c_str(),
			(void *) &sin.sin_addr,
			sizeof(sin.sin_addr));
	sin.sin_port = htons(port_num);

	/* Bind the socket to the specified port number */
	if (bind(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		fprintf(stderr, "Could not bind the socket\n");
		goto fail;
	}

	/* Specify that this is a listener socket */
	if (listen(sock, SOMAXCONN) < 0) {
		fprintf(stderr, "Failed to listen on this socket\n");
		goto fail;
	}

    if ((csock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Cannot create a socket\n");
		return (-1);
	}
	if (connect(csock, (const sockaddr *) &sin, sizeof(sin))) {
        fprintf(stderr, "Failed to connect to server\n");
        return (-1);
    }
    if (accepted_fd = accept(sock, (struct sockaddr *) &csin, &csin_len) < 0) {
        fprintf(stderr, "Failed to accept to server\n");
        return (-1);
    }
    return (0);

fail:
	close(sock);
	return (-1);
}

int server(const char *conn_str, const char *ca_pem,
           const char *cert_pem, const char *key_pem) {
    static char buffer[BUFSIZE];
    uint32_t len;
    std::string host;
    uint16_t port;
    int csock = -1, accepted_fd = -1; 
    get_host_port(conn_str, host, port);
    Ssl::Socket s(host, port, std::string(ca_pem), std::string(cert_pem), std::string(key_pem));
    s.listen();
    proxy_to_clear_conn(host, port+1, csock, accepted_fd);
    const Ssl::Socket *accepted = s.accept();
    while (true) {
        len = BUFSIZE;
        accepted->recv((uint8_t *) buffer, len);
        fprintf(stderr, "Recv %i\n", len);
        if (len == 0) {
            fprintf(stderr, "Client closed connection\n");
            return -1;
        }
        send(csock, buffer, (int) len, 0);
        recv(accepted_fd, buffer, (int) len, 0);
        int res = accepted->send((const uint8_t *) buffer, len);
        fprintf(stderr, "Sent %i\n", res);
    }
    return (0);
}
