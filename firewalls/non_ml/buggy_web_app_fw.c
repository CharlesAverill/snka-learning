/*
 * firewall_oracle_buggy.c
 *
 * !! INTENTIONALLY BUGGY - FOR DIFFERENTIAL TESTING ONLY !!
 *
 * This file is a labeled corpus example for a firewall bug-detection tool.
 * It is identical to firewall_oracle_correct.c except for one deliberate
 * parsing error described below.
 *
 * ── BUG: missing ntohs() on src_port and dst_port ───────────────────────
 *
 * Location : parse_packet(), offset 2 (src_port) and offset 4 (dst_port)
 * Root cause: the raw big-endian bytes are cast directly to uint16_t on a
 *             little-endian host without calling ntohs(), so the byte order
 *             is silently reversed.
 *
 * Consequence (little-endian host, e.g. x86-64):
 *   Sent port  │ Wire bytes │ Correct parse │ Buggy parse
 *   ───────────┼────────────┼───────────────┼────────────
 *        80    │ 00 50      │    80         │   20480   (0x5000)
 *       443    │ 01 BB      │   443         │   47873   (0xBB01)
 *        53    │ 00 35      │    53         │   13568   (0x3500)
 *
 * Observable misclassification:
 *   - Inbound TCP to port 80 or 443 → always DRP (dst_port never matches)
 *   - Outbound UDP to port 53 (DNS)  → always DRP (dst_port never matches)
 *   - A packet sent with raw port value 20480 would be accepted as if it
 *     were port 80, bypassing the port allowlist check entirely.
 *
 * Note: payload_len is also affected by the same bug (offset 7), so the
 * length bounds check (0 < len <= 9000) may also misfire, but the port
 * misclassification is the most security-relevant consequence.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -pthread -o firewall_oracle_buggy firewall_oracle_buggy.c
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOST        "0.0.0.0"
#define PORT        9000
#define PACKET_SIZE 13

#define POOL_SIZE  16
#define QUEUE_CAP  256

typedef struct {
    int     fds[QUEUE_CAP];
    int     head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} work_queue_t;

static work_queue_t wq;

static void wq_init(work_queue_t *q)
{
    q->head = q->tail = q->count = 0;
    pthread_mutex_init(&q->lock,      NULL);
    pthread_cond_init (&q->not_empty, NULL);
    pthread_cond_init (&q->not_full,  NULL);
}

static void wq_push(work_queue_t *q, int fd)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == QUEUE_CAP)
        pthread_cond_wait(&q->not_full, &q->lock);
    q->fds[q->tail] = fd;
    q->tail = (q->tail + 1) % QUEUE_CAP;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

static int wq_pop(work_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == 0)
        pthread_cond_wait(&q->not_empty, &q->lock);
    int fd = q->fds[q->head];
    q->head = (q->head + 1) % QUEUE_CAP;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return fd;
}

typedef struct {
    uint8_t  protocol;
    uint8_t  direction;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ttl;
    uint16_t payload_len;
    uint8_t  src_ip[4];
} packet_t;

static int recv_exact(int fd, void *buf, size_t n)
{
    size_t received = 0;
    uint8_t *p = (uint8_t *)buf;
    while (received < n) {
        ssize_t r = recv(fd, p + received, n - received, 0);
        if (r <= 0)
            return -1;
        received += (size_t)r;
    }
    return 0;
}

/*
 * BUG IS HERE.
 *
 * The memcpy + cast reads bytes in host (little-endian) order.
 * The fix is to wrap each assignment with ntohs() - as done in the
 * correct version - but that call is intentionally omitted here.
 *
 * Diff vs correct version (parse_packet only):
 *
 * -    pkt->src_port    = ntohs(sp);
 * -    pkt->dst_port    = ntohs(dp);
 * -    pkt->payload_len = ntohs(pl);
 * +    pkt->src_port    = sp;          // BUG: host byte order, not network
 * +    pkt->dst_port    = dp;          // BUG: host byte order, not network
 * +    pkt->payload_len = pl;          // BUG: host byte order, not network
 */
static void parse_packet(const uint8_t *buf, packet_t *pkt)
{
    pkt->protocol  = buf[0];
    pkt->direction = buf[1];

    uint16_t sp, dp, pl;
    memcpy(&sp, buf + 2, sizeof(uint16_t));
    memcpy(&dp, buf + 4, sizeof(uint16_t));
    memcpy(&pl, buf + 7, sizeof(uint16_t));
    pkt->src_port    = sp;   /* BUG: should be ntohs(sp) */
    pkt->dst_port    = dp;   /* BUG: should be ntohs(dp) */
    pkt->payload_len = pl;   /* BUG: should be ntohs(pl) */

    pkt->ttl       = buf[6];
    pkt->src_ip[0] = buf[9];
    pkt->src_ip[1] = buf[10];
    pkt->src_ip[2] = buf[11];
    pkt->src_ip[3] = buf[12];
}

/* Classification logic is identical to the correct version. */

static int is_rfc1918(const uint8_t ip[4])
{
    return (ip[0] == 10) ||
           (ip[0] == 192 && ip[1] == 168) ||
           (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31);
}

static int is_valid_proto(uint8_t proto)
{
    return proto == 6 || proto == 17 || proto == 1;
}

static int classify(const packet_t *pkt)
{
    if (!is_valid_proto(pkt->protocol))
        return 0;
    if (pkt->ttl <= 1)
        return 0;
    if (pkt->payload_len == 0 || pkt->payload_len > 9000)
        return 0;

    if (pkt->direction == 0) {
        if (is_rfc1918(pkt->src_ip))
            return 0;
        if (pkt->protocol != 6)
            return 0;
        if (pkt->dst_port != 80 && pkt->dst_port != 443)
            return 0;
        return 1;
    } else {
        if (pkt->src_port > 1023)
            return 1;
        if (pkt->protocol == 17 && pkt->dst_port == 53)
            return 1;
        return 0;
    }
}

static void *worker(void *arg)
{
    (void)arg;
    uint8_t buf[PACKET_SIZE];

    for (;;) {
        int fd = wq_pop(&wq);

        for (;;) {
            if (recv_exact(fd, buf, PACKET_SIZE) != 0)
                break;

            packet_t pkt;
            parse_packet(buf, &pkt);

            int         decision = classify(&pkt);
            const char *rsp      = decision ? "FWD" : "DRP";

            printf("[*] proto=%u dir=%u src=%u.%u.%u.%u sp=%u dp=%u ttl=%u len=%u  ->  %s\n",
                   pkt.protocol, pkt.direction,
                   pkt.src_ip[0], pkt.src_ip[1], pkt.src_ip[2], pkt.src_ip[3],
                   pkt.src_port, pkt.dst_port,
                   pkt.ttl, pkt.payload_len, rsp);

            if (send(fd, rsp, 3, MSG_NOSIGNAL) != 3)
                break;
        }

        close(fd);
    }
    return NULL;
}

int main(void)
{
    wq_init(&wq);
    pthread_t threads[POOL_SIZE];
    for (int i = 0; i < POOL_SIZE; i++) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            perror("pthread_create"); exit(EXIT_FAILURE);
        }
        pthread_detach(threads[i]);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(EXIT_FAILURE);
    }
    if (listen(server_fd, QUEUE_CAP) < 0) {
        perror("listen"); exit(EXIT_FAILURE);
    }

    printf("Buggy firewall oracle listening on %s:%d (%d workers)\n",
           HOST, PORT, POOL_SIZE);

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int conn_fd = accept(server_fd,
                             (struct sockaddr *)&client_addr, &client_len);
        if (conn_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept"); continue;
        }
        printf("[+] connection from %s\n", inet_ntoa(client_addr.sin_addr));
        wq_push(&wq, conn_fd);
    }
}
