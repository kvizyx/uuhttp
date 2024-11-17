#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8080

#define QUEUE_SIZE 4096
#define EPOLL_MAX_EVENTS 128
#define RD_BUF_CHUNK_SIZE 4096

#define HANDLE_ERRNO(msg) fprintf(stderr, "%s: %s\n", msg, strerror(errno));

enum HTTP_METHOD {
    GET     = 0,
    POST    = 1,
    PUT     = 2,
    PATCH   = 3,
    DELETE  = 4,
    OPTIONS = 5,
    TRACE   = 6,
    HEAD    = 7,
    CONNECT = 8
};

struct http_request {
    char* path;
    enum HTTP_METHOD method;

    int _error;
};

struct http_server {
    int fd;
    int ep_fd;
    struct epoll_event* ep_ev_buf;
    struct sockaddr_in sa;
    socklen_t sa_len;
};

struct http_server* hs_init() {
    struct http_server* srv = malloc(sizeof(struct http_server));
    assert(srv != NULL);

    struct sockaddr_in addr = {0};

    addr.sin_addr.s_addr = inet_addr(SERVER_HOST);
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_family = AF_INET;

    const int ep_fd = epoll_create1(0);
    if (ep_fd < 0) {
        HANDLE_ERRNO("Failed to create epoll instance");
        return NULL;
    }

    struct epoll_event* ep_ev_buf = calloc(EPOLL_MAX_EVENTS, sizeof(struct epoll_event));
    assert(ep_ev_buf != NULL);

    srv->ep_fd = ep_fd;
    srv->ep_ev_buf = ep_ev_buf;
    srv->sa = addr;
    srv->sa_len = sizeof(addr);

    return srv;
}

void hs_handle(struct http_server* srv, const struct http_request req) {}

static void hs_conn_read();
static void hs_conn_write();

static int hs_conn_accept(const struct http_server* srv) {
    struct sockaddr sa_in;
    socklen_t sa_in_len;

    const int cfd = accept(srv->fd, &sa_in, &sa_in_len);
    if (cfd < 0) {
        HANDLE_ERRNO("Failed to accept connection");
        return -1;
    }

    struct epoll_event ep_ev = {
        .events = EPOLLIN | EPOLLET,
        .data.fd = cfd
    };

    if (epoll_ctl(srv->ep_fd, EPOLL_CTL_ADD, cfd, &ep_ev) < 0) {
        HANDLE_ERRNO("Failed to add entry to the epoll instance");
        return -1;
    }

    return 0;
}

struct http_request http_request_parse(const char* bytes, const size_t size) {
    struct http_request req = {0};

    char* buf = malloc(size);
    if (!buf) {
        req._error = 1;
        return req;
    }

    for (size_t i = 0; i < size; ++i) {
        buf[i] = bytes[i];
    }

    // ...

    free(buf);

    return req;
}

void hs_serve(struct http_server* srv) {
    const int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sfd < 0) {
        HANDLE_ERRNO("Failed to create socket");
        return;
    }

    const int option = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    srv->fd = sfd;

    if (bind(sfd, (struct sockaddr*)&srv->sa, srv->sa_len) < 0) {
        HANDLE_ERRNO("Failed to bind socket");
        return;
    }

    if (listen(sfd, QUEUE_SIZE) < 0) {
        HANDLE_ERRNO("Failed to listen");
        return;
    }

    struct epoll_event ep_ev_in = {
        .events = EPOLLIN | EPOLLET,
        .data.fd = sfd
    };

    if (epoll_ctl(srv->ep_fd, EPOLL_CTL_ADD, sfd, &ep_ev_in) < 0) {
        HANDLE_ERRNO("Failed to add server fd to the epoll instance");
        return;
    }

    int ev_count = 0;

    while (true) {
        ev_count = epoll_wait(srv->ep_fd, srv->ep_ev_buf, EPOLL_MAX_EVENTS, -1);
        if (ev_count < 0) {
            HANDLE_ERRNO("Failed to receive epoll events")
            break;
        }

        for (size_t i = 0; i < ev_count; ++i) {
            const struct epoll_event ev = srv->ep_ev_buf[i];

            if (ev.events & (EPOLLHUP | EPOLLERR)) {
                close(ev.data.fd);
                continue;
            }

            if (ev.data.fd == srv->fd) {
                hs_conn_accept(srv);
                continue;
            }

            size_t payload_size = 0;
            char* rd_buf = malloc(RD_BUF_CHUNK_SIZE);
            if (!rd_buf) {
                fprintf(stderr, "Failed to allocate memory for the read buffer\n");
                return;
            };

            int n = 0;

            while (true) {
                char tmp_buf[RD_BUF_CHUNK_SIZE];

                const ssize_t bytes_rd = recv(ev.data.fd, tmp_buf, RD_BUF_CHUNK_SIZE, 0);
                if (bytes_rd < 0) {
                    HANDLE_ERRNO("Failed to receive");
                    break;
                }

                if (bytes_rd == 0) {
                    break;
                }

                payload_size += bytes_rd;
                const size_t offset = n * RD_BUF_CHUNK_SIZE;

                for (size_t j = 0; j < bytes_rd; ++j) {
                    rd_buf[j + offset] = tmp_buf[j];
                }

                if (bytes_rd < RD_BUF_CHUNK_SIZE) {
                    break;
                }

                ++n;

                char* tmp_rd_buf = rd_buf;

                rd_buf = realloc(tmp_rd_buf, (n + 1) * RD_BUF_CHUNK_SIZE);
                if (!rd_buf) {
                    free(rd_buf);
                    fprintf(stderr, "Failed to reallocate memory for the read buffer\n");
                    return;
                };

                rd_buf = tmp_rd_buf;
            }

            const struct http_request req = http_request_parse(rd_buf, payload_size);
            free(rd_buf);

            if (!req._error) {
                hs_handle(srv, req);
            }

            close(ev.data.fd);
        }
    }
}

void hs_free(struct http_server* server) {
    assert(server != NULL);

    close(server->ep_fd);

    free(server->ep_ev_buf);
    free(server);
}

int main(const int argc, char **argv) {
    struct http_server* srv = hs_init();
    assert(srv != NULL);

    hs_serve(srv);
    hs_free(srv);

    return EXIT_SUCCESS;
}