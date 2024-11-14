#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define INDEX_PATH "assets/index.html"
#define NOT_FOUND_PATH "assets/404.html"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8080

#define QUEUE_SIZE 4096

struct content_buffers {
    char* buf_index;
    char* buf_not_found;
};

char* alloc_from_file(const char* filepath) {
    FILE* fp = fopen(filepath, "r");
    if (fp < 0) {
        fprintf(stderr, "Failed to open '%s': %s\n", filepath, strerror(errno));
        return NULL;
    }

    struct stat st;

    if (stat(filepath, &st) < 0) {
        fprintf(stderr, "Failed to get stat for %s: %s\n", filepath, strerror(errno));
        fclose(fp);
        return NULL;
    }

    const size_t buf_size = st.st_size + 1;

    char* buf = malloc(sizeof(char) * buf_size);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    const size_t bytes_written = fread(buf, sizeof(char), buf_size, fp);
    if (bytes_written != buf_size-1) {
        fprintf(stderr, "Failed to read into buffer, wrote %ld/%ld\n", bytes_written, buf_size);
        fclose(fp);
        return NULL;
    }

    // End buffer with content-closing tag.
    buf[buf_size-1] = '\0';

    return buf;
}

struct content_buffers* cb_alloc(const char* index_path) {
    struct content_buffers* cb = malloc(sizeof(struct content_buffers));
    assert(cb != NULL);

    cb->buf_index = alloc_from_file(index_path);
    assert(cb->buf_index != NULL);

    cb->buf_not_found = alloc_from_file(NOT_FOUND_PATH);
    assert(cb->buf_not_found != NULL);

    return cb;
}

void cb_free(struct content_buffers* cb) {
    assert(cb != NULL);

    free(cb->buf_index);
    free(cb->buf_not_found);

    free(cb);
}

int serve_content(struct content_buffers* cb) {
    struct sockaddr_in server_addr = {0};

    server_addr.sin_addr.s_addr = inet_addr(SERVER_HOST);
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_family = AF_INET;

    // Size of the server address struct.
    socklen_t sa_len = sizeof(server_addr);

    const int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    int option = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (bind(server_fd, (struct sockaddr*)&server_addr, sa_len) < 0) {
        fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (listen(server_fd, QUEUE_SIZE) < 0) {
        fprintf(stderr, "Failed to listen: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    printf("Listening on http://%s:%d\n", SERVER_HOST, SERVER_PORT);

    while (1) {
        const int conn_fd = accept(server_fd, (struct sockaddr*)&server_addr, &sa_len);
        if (conn_fd < 0) {
            fprintf(stderr, "Failed to accept: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        size_t content_length = strlen(cb->buf_index);

        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s";

        char response_buffer[300];

        sprintf(response_buffer, response, content_length, cb->buf_index);

        long total = 0;
        const size_t required = sizeof(response_buffer);

        while (total < required) {
            const long sent_bytes = send(conn_fd, response_buffer, 300, 0);
            if (sent_bytes < 0) {
                fprintf(stderr, "Failed to send: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }

            total += sent_bytes;
        }

        close(conn_fd);
    }
}

int main(const int argc, char **argv) {
    const char* index_path = INDEX_PATH;

    if (argc > 1) {
        index_path = argv[1];
    }

    struct content_buffers* cb = cb_alloc(index_path);
    assert(cb != NULL);

    serve_content(cb);

    cb_free(cb);

    return EXIT_SUCCESS;
}