# Two-way SSL authentication example in C and in Elixir

A simple example program that demonstrates two-way authentication between a client
and the server.

Note: For the C code, don't plugin this code directly into multi-threaded applications, you need to call some additional routines so that OpenSSL routines become reentrant.

## Steps to run the example

### Pre-requisities
* Any decent C compiler
* OpenSSL development library

### Build (keys and code)

    make

### Build (code only)

    make build

### Change server domain

Modify `S_DOMAIN=localhost` in `Makefile`

### Server

    make start_server


### Client

    make start_client

### Elixir server with client auth on UID (userid)

    elixir elixir/server.exs 8443 1000