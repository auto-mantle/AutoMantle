#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/vm_sockets.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROXY_PORT 3128
#define MAX_CONNECTIONS 16
static atomic_int connections = 0;

struct pair { int source; int target; };
static void *relay(void *argument) {
    struct pair *p = argument;
    char buffer[8192];
    for (;;) {
        ssize_t count = recv(p->source, buffer, sizeof buffer, 0);
        if (count <= 0) break;
        for (ssize_t done = 0; done < count;) {
            ssize_t sent = send(p->target, buffer + done, (size_t)(count - done), MSG_NOSIGNAL);
            if (sent <= 0) { count = -1; break; }
            done += sent;
        }
        if (count < 0) break;
    }
    shutdown(p->target, SHUT_WR);
    return NULL;
}
static void *serve(void *argument) {
    int client = *(int *)argument;
    free(argument);
    int host = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (host < 0) goto done;
    struct sockaddr_vm address = {0};
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_HOST;
    address.svm_port = PROXY_PORT;
    if (connect(host, (struct sockaddr *)&address, sizeof address) < 0) goto done_host;
    struct timeval timeout = {.tv_sec = 300};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(host, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    struct pair upstream = {.source = client, .target = host};
    struct pair downstream = {.source = host, .target = client};
    pthread_t worker;
    if (pthread_create(&worker, NULL, relay, &upstream) == 0) {
        relay(&downstream);
        pthread_join(worker, NULL);
    }
done_host:
    close(host);
done:
    close(client);
    atomic_fetch_sub(&connections, 1);
    return NULL;
}
int main(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) { perror("socket"); return 1; }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(PROXY_PORT);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof address) < 0 || listen(listener, MAX_CONNECTIONS) < 0) {
        perror("listen"); close(listener); return 1;
    }
    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        if (atomic_fetch_add(&connections, 1) >= MAX_CONNECTIONS) {
            atomic_fetch_sub(&connections, 1); close(client); continue;
        }
        int *owned = malloc(sizeof *owned);
        if (!owned) { atomic_fetch_sub(&connections, 1); close(client); continue; }
        *owned = client;
        pthread_t worker;
        if (pthread_create(&worker, NULL, serve, owned) != 0) {
            free(owned); atomic_fetch_sub(&connections, 1); close(client); continue;
        }
        pthread_detach(worker);
    }
    close(listener);
    return 1;
}
