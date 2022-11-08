# Two-way SSL authentication example in C

A simple example program that demonstrates two-way authentication between a client
and the server.

There are a couple of things to be noted here:

1. Don't plugin this code directly into multi-threaded applications, you need to call some additional routines so that OpenSSL routines become reentrant.
2. You can generate the keys by looking at [this gist](https://gist.github.com/zapstar/4b51d7cfa74c7e709fcdaace19233443).

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