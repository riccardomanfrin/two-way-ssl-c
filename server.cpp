/*
 *  server.c
 *  OpenSSL
 *
 *  Created by Thirumal Venkat on 18/05/16.
 *  Copyright © 2016 Thirumal Venkat. All rights reserved.
 */


#include <string>
#include <string.h>
#include "sslsocket.h"

/* Global variable that indicates work is present */
static int do_work = 1;

/* Buffer size to be used for transfers */
#define BUFSIZE 128

static int get_host_port(const char *conn_str, std::string &addr , uint16_t &port) {
    char buff[BUFSIZE];
    strcpy(buff, conn_str);
    addr = std::string(strtok(buff, ":"));
    port = (uint16_t) atoi(strtok(NULL, ":"));
    return 0;
}

int server(const char *conn_str, const char *ca_pem,
           const char *cert_pem, const char *key_pem) {
    static char buffer[BUFSIZE];
    uint32_t len;
    std::string host;
    uint16_t port;
    get_host_port(conn_str, host, port);
    SSLSocket s(host, port, std::string(ca_pem), std::string(cert_pem), std::string(key_pem));
    s.listen();
    const SSLSocket *accepted = s.accept();
    while (true) {
        len = BUFSIZE;
        accepted->recv((uint8_t *) buffer, len);
        fprintf(stderr, "Recv %i\n", len);
        int res = accepted->send((const uint8_t *) buffer, len);
        fprintf(stderr, "Sent %i\n", res);
    }
}