/*
 *  client.c
 *  OpenSSL
 *
 *  Created by Thirumal Venkat on 18/05/16.
 *  Copyright © 2016 Thirumal Venkat. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sslsocket.h"
#include "client.h"

#define BUFSIZE 128

int get_host_port(const char *conn_str, std::string &addr , uint16_t &port) {
    char buff[BUFSIZE];
    strcpy(buff, conn_str);
    addr = std::string(strtok(buff, ":"));
    port = (uint16_t) atoi(strtok(NULL, ":"));
    return 0;
}

int client(const char *conn_str, const char *ca_pem,
           const char *cert_pem, const char *key_pem) {
    char buffer[BUFSIZE];
    uint32_t len = BUFSIZE;
    std::string host;
    uint16_t port;
    get_host_port(conn_str, host, port);
    SSLSocket s(host, port, std::string(ca_pem), std::string(cert_pem), std::string(key_pem));
    s.connect();
    while (true) {
        fgets(buffer, BUFSIZE, stdin);
        int res = s.send((const uint8_t *) buffer, strlen(buffer));
        fprintf(stderr, "Sent %i\n", res);
        memset(buffer, 0, BUFSIZE);
        s.recv((uint8_t *) buffer, len);
        fprintf(stderr, "Recv %s\n", buffer);
    }
    return (0);
}
