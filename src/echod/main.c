/*
 * echod: a tiny single-threaded echo server (and UDP echo) built to make the
 * kernel's TCP behaviours visible: accept queues, backpressure, half-close,
 * TIME_WAIT, RST-on-close-with-unread-data, idle reaping.
 *
 * Architecture (docs/phase4.md section 3):
 *   - one epoll loop, nonblocking sockets, accept4(SOCK_CLOEXEC)
 *   - connection slab: fixed array of max_conns, free list, no per-conn malloc
 *   - 64K+64K rbuf/wbuf per conn; "buffer full -> drop EPOLLIN, arm EPOLLOUT"
 *     is the only backpressure mechanism (we never grow, never block)
 *   - read 0 -> flush pending output -> shutdown(SHUT_WR); a conn is closed
 *     only when the peer closes or the idle timer fires
 *   - signalfd (SIGINT/SIGTERM) and timerfd (idle) live in the epoll set
 *   - at capacity: default accept-and-close; --no-accept stops accepting
 *   - EMFILE/ENFILE: spare-fd trick so the loop never busy-spins
 *
 * This tool only talks to sockets whose peer the guard allows; every payload
 * byte it echoes back is untrusted data (echo servers are their own HazMat).
 */
#include "nettk.h"
#include "guard.h"
#include "clock.h"
#include "opts.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define NT_RBUF (64 * 1024)
#define NT_WBUF (64 * 1024)
#define NT_UDPSZ 65535
#define NT_MAXEV 64

enum conn_state { S_FREE, S_LISTEN, S_HANDLING, S_CLOSING };

enum close_cause {
    C_NONE = 0,
    C_FIN,      /* peer sent FIN and we finished the swap */
    C_RST,      /* ECONNRESET / EPIPE / EPOLLERR */
    C_TIMEOUT,  /* idle reaper */
    C_ERROR,    /* other socket error */
    C_SHUTDOWN, /* server asked to stop */
};

struct conn {
    struct conn *next;          /* free list */
    int fd;
    int state;
    int shutdown_sent;          /* already called shutdown(SHUT_WR) */
    uint8_t rbuf[NT_RBUF];
    size_t rlen;
    uint8_t wbuf[NT_WBUF];
    size_t wlen, woff;
    uint64_t last_activity_ns;
    uint64_t bytes_in, bytes_out;
};

struct echod {
    /* options */
    int family;                 /* 4 or 6 */
    int et;                     /* --et: EPOLLET everywhere */
    int udp;
    int stop_accept;            /* --no-accept */
    int idle_ms;
    int stats;
    int nodelay, quickack, cork, linger0, keepalive;
    int backlog;
    int max_conns;
    const char *bind_text;
    int port;

    /* runtime */
    struct conn *slab;          /* max_conns entries */
    struct conn *free_head;
    int efd, lfd, sigfd, tfd;   /* epoll / listener or udp / signalfd / timerfd */
    int spare_fd;               /* EMFILE trick */
    int accepting;              /* listener currently armed */
    int active;                 /* conns in HANDLING or CLOSING */
    int shutting_down;

    /* stats */
    uint64_t accepted, refused;
    uint64_t fin_closed, rst_closed, to_closed, err_closed, shutdown_closed;
    uint64_t bytes_in, bytes_out;
    uint64_t udp_dgrams_in, udp_dgrams_out, udp_trunc;
    uint64_t peak;
};

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s --bind ADDR -p PORT [--backlog N] [--max-conns N] [-u]\n"
            "           [--no-accept] [--et] [--idle SEC] [--stats]\n"
            "           [--nodelay] [--quickack] [--cork] [--linger0] [--keepalive]\n"
            "           [-4|-6]\n"
            "  echo server; --bind is required (lab/loopback/wildcard address)\n",
            prog);
}

static void slab_init(struct echod *ec)
{
    ec->slab = calloc((size_t)ec->max_conns, sizeof *ec->slab);
    if (ec->slab == NULL) {
        fprintf(stderr, "echod: calloc(%d conns): %s\n", ec->max_conns, strerror(errno));
        exit(2);
    }
    ec->free_head = NULL;
    for (int i = 0; i < ec->max_conns; i++) {
        ec->slab[i].state = S_FREE;
        ec->slab[i].fd = -1;
        ec->slab[i].next = ec->free_head;
        ec->free_head = &ec->slab[i];
    }
}

static struct conn *conn_alloc(struct echod *ec)
{
    struct conn *c = ec->free_head;
    if (c != NULL) {
        ec->free_head = c->next;
        c->next = NULL;
    }
    return c;
}

static struct conn *conn_by_fd(const struct echod *ec, int fd)
{
    for (int i = 0; i < ec->max_conns; i++) {
        if (ec->slab[i].fd == fd) {
            return &ec->slab[i];
        }
    }
    return NULL;
}

static void conn_free(struct echod *ec, struct conn *c)
{
    c->state = S_FREE;
    c->fd = -1;
    c->next = ec->free_head;
    ec->free_head = c;
}

static void arm_listener(struct echod *ec, int on)
{
    if (ec->accepting == on) {
        return;
    }
    struct epoll_event ev = { .events = (uint32_t)(on ? EPOLLIN : 0), .data.fd = ec->lfd };
    if (ec->et && on) {
        ev.events |= EPOLLET;
    }
    if (epoll_ctl(ec->efd, EPOLL_CTL_MOD, ec->lfd, &ev) != 0) {
        perror("echod: epoll_ctl(listener)");
    }
    ec->accepting = on;
}

/* Recompute a conn's event mask from its buffers and state. This is the whole
 * backpressure mechanism: no EPOLLIN while we hold unqueued input (rlen>0) or
 * while our output queue is full, no EPOLLOUT once the queue drains. */
static void set_conn_events(struct echod *ec, struct conn *c)
{
    uint32_t ev = 0;
    if (c->state == S_HANDLING) {
        if (c->rlen == 0) {
            ev |= EPOLLIN;
        }
        if (c->wlen > c->woff) {
            ev |= EPOLLOUT;
        }
    } else if (c->state == S_CLOSING) {
        if (c->wlen > c->woff) {
            ev |= EPOLLOUT; /* still flushing before our FIN */
        }
        if (c->shutdown_sent) {
            ev |= EPOLLIN; /* FIN sent; waiting for the peer's FIN */
        }
    }
    if (ec->et) {
        ev |= EPOLLET;
    }
    struct epoll_event mev = { .events = ev, .data.fd = c->fd };
    if (epoll_ctl(ec->efd, EPOLL_CTL_MOD, c->fd, &mev) != 0) {
        perror("echod: epoll_ctl(conn)");
    }
}

static void stats_print(const struct echod *ec)
{
    fprintf(stderr,
            "echod: accepted=%llu refused=%llu peak=%llu "
            "closed{fin=%llu rst=%llu timeout=%llu err=%llu shutdown=%llu} "
            "bytes_in=%llu bytes_out=%llu udp{in=%llu out=%llu trunc=%llu}\n",
            (unsigned long long)ec->accepted,
            (unsigned long long)ec->refused,
            (unsigned long long)ec->peak,
            (unsigned long long)ec->fin_closed,
            (unsigned long long)ec->rst_closed,
            (unsigned long long)ec->to_closed,
            (unsigned long long)ec->err_closed,
            (unsigned long long)ec->shutdown_closed,
            (unsigned long long)ec->bytes_in,
            (unsigned long long)ec->bytes_out,
            (unsigned long long)ec->udp_dgrams_in,
            (unsigned long long)ec->udp_dgrams_out,
            (unsigned long long)ec->udp_trunc);
}

static void conn_close(struct echod *ec, struct conn *c, int cause)
{
    switch (cause) {
    case C_FIN:      ec->fin_closed++; break;
    case C_RST:      ec->rst_closed++; break;
    case C_TIMEOUT:  ec->to_closed++; break;
    case C_ERROR:    ec->err_closed++; break;
    default:         ec->shutdown_closed++; break;
    }
    /* Note: if rlen>0 or unsent wbuf remained, this close() makes the kernel
     * send RST instead of FIN (unread incoming data). That is the documented
     * behaviour we test explicitly in the lab. */
    if (c->fd >= 0) {
        if (ec->linger0 && c->state != S_FREE) {
            struct linger lg = { .l_onoff = 1, .l_linger = 0 };
            setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        }
        epoll_ctl(ec->efd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    ec->bytes_in += c->bytes_in;
    ec->bytes_out += c->bytes_out;
    ec->active--;
    c->bytes_in = c->bytes_out = 0;
    conn_free(ec, c);
    if (ec->stop_accept && !ec->accepting) {
        arm_listener(ec, 1); /* capacity freed: resume accepting */
    }
}

static void evac_rbuf(struct conn *c)
{
    while (c->rlen > 0 && c->wlen < NT_WBUF) {
        size_t n = c->rlen < NT_WBUF - c->wlen ? c->rlen : NT_WBUF - c->wlen;
        memcpy(c->wbuf + c->wlen, c->rbuf, n);
        c->wlen += n;
        memmove(c->rbuf, c->rbuf + n, c->rlen - n);
        c->rlen -= n;
    }
}

/* Read until EAGAIN (required under EPOLLET, harmless under LT). */
static void conn_read(struct echod *ec, struct conn *c)
{
    for (;;) {
        if (c->rlen >= NT_RBUF) {
            break; /* staging full: give the peer real backpressure */
        }
        ssize_t n = read(c->fd, c->rbuf + c->rlen, NT_RBUF - c->rlen);
        if (n > 0) {
            c->rlen += (size_t)n;
            c->bytes_in += (uint64_t)n;
            c->last_activity_ns = nt_now_ns();
        } else if (n == 0) {
            /* peer FIN. Keep reading until we flush; then send our FIN. */
            c->state = S_CLOSING;
            evac_rbuf(c);
            if (c->wlen == 0 && !c->shutdown_sent) {
                if (shutdown(c->fd, SHUT_WR) == 0) {
                    c->shutdown_sent = 1;
                }
            }
            set_conn_events(ec, c);
            return;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == ECONNRESET) {
            conn_close(ec, c, C_RST);
            return;
        } else {
            perror("echod: read");
            conn_close(ec, c, C_ERROR);
            return;
        }
    }
    evac_rbuf(c);
    set_conn_events(ec, c);
}

static void conn_write(struct echod *ec, struct conn *c)
{
    while (c->woff < c->wlen) {
        ssize_t n = write(c->fd, c->wbuf + c->woff, c->wlen - c->woff);
        if (n > 0) {
            c->woff += (size_t)n;
            c->bytes_out += (uint64_t)n;
            c->last_activity_ns = nt_now_ns();
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EPIPE || errno == ECONNRESET) {
            conn_close(ec, c, C_RST);
            return;
        } else {
            perror("echod: write");
            conn_close(ec, c, C_ERROR);
            return;
        }
    }
    if (c->woff == c->wlen) {
        c->wlen = c->woff = 0; /* drained */
        evac_rbuf(c);
        if (c->state == S_CLOSING && c->wlen == 0 && !c->shutdown_sent) {
            if (shutdown(c->fd, SHUT_WR) == 0) {
                c->shutdown_sent = 1;
            }
        }
    }
    set_conn_events(ec, c);
}

static void apply_conn_opts(const struct echod *ec, int fd)
{
    int one = 1;
    if (ec->nodelay) {
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    if (ec->quickack) {
        setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof one);
    }
    if (ec->cork) {
        setsockopt(fd, IPPROTO_TCP, TCP_CORK, &one, sizeof one);
    }
    if (ec->keepalive) {
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
        int idle = 60, intvl = 10, cnt = 3;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
    }
}

static void accept_conns(struct echod *ec)
{
    for (;;) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof peer;
        int fd = accept4(ec->lfd, (struct sockaddr *)&peer, &plen,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }
            if ((errno == EMFILE || errno == ENFILE) && ec->spare_fd >= 0) {
                /* Reserve-spare trick: free one fd so accept succeeds, take the
                 * connection and immediately refuse it, then reopen the spare.
                 * Without this the loop would never drain the queue. */
                close(ec->spare_fd);
                ec->spare_fd = -1;
                int fd2 = accept4(ec->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd2 >= 0) {
                    close(fd2);
                    ec->refused++;
                }
                ec->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
                break;
            }
            perror("echod: accept4");
            break;
        }
        if (ec->active >= ec->max_conns) {
            if (ec->stop_accept) {
                /* --no-accept: do not touch the accept queue at all. The new
                 * connection stays handshake-completed in the kernel backlog
                 * (visible in `ss -ltn` Recv-Q) until we free a slot. */
                arm_listener(ec, 0);
                break;
            }
            /* default accept-and-close: the refused client gets a prompt EOF
             * instead of stalling in the SYN queue. */
            close(fd);
            ec->refused++;
            continue;
        }
        ec->accepted++;
        struct conn *c = conn_alloc(ec);
        if (c == NULL) {
            close(fd);
            ec->refused++;
            break;
        }
        memset(c->rbuf, 0, NT_RBUF);
        memset(c->wbuf, 0, NT_WBUF);
        c->fd = fd;
        c->state = S_HANDLING;
        c->shutdown_sent = 0;
        c->rlen = c->wlen = c->woff = 0;
        c->last_activity_ns = nt_now_ns();
        apply_conn_opts(ec, fd);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
        if (ec->et) {
            ev.events |= EPOLLET;
        }
        if (epoll_ctl(ec->efd, EPOLL_CTL_ADD, fd, &ev) != 0) {
            perror("echod: epoll_ctl(add conn)");
            conn_free(ec, c);
            close(fd);
            break;
        }
        ec->active++;
        if ((uint64_t)ec->active > ec->peak) {
            ec->peak = (uint64_t)ec->active;
        }
    }
}

static void udp_handle(struct echod *ec)
{
    for (;;) {
        uint8_t buf[NT_UDPSZ];
        struct sockaddr_storage from;
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof buf };
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_name = &from;
        mh.msg_namelen = sizeof from;
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        ssize_t n = recvmsg(ec->lfd, &mh, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            perror("echod: recvmsg");
            return;
        }
        ec->udp_dgrams_in++;
        ec->bytes_in += (uint64_t)n;
        if (mh.msg_flags & MSG_TRUNC) {
            ec->udp_trunc++; /* datagram lost its tail; do not echo garbage */
        } else {
            struct iovec oiov = { .iov_base = buf, .iov_len = (size_t)n };
            struct msghdr omh;
            memset(&omh, 0, sizeof omh);
            omh.msg_name = &from; /* echo back to whoever sent it */
            omh.msg_namelen = mh.msg_namelen;
            omh.msg_iov = &oiov;
            omh.msg_iovlen = 1;
            if (sendmsg(ec->lfd, &omh, 0) >= 0) {
                ec->udp_dgrams_out++;
                ec->bytes_out += (uint64_t)n;
            } else if (errno != EAGAIN && errno != EINTR) {
                perror("echod: sendmsg");
            }
        }
        if (!ec->et) {
            break; /* LT: one datagram per unit */
        }
    }
}

static void timer_tick(struct echod *ec)
{
    uint64_t expirations;
    if (read(ec->tfd, &expirations, sizeof expirations) != sizeof expirations) {
        return;
    }
    uint64_t now = nt_now_ns();
    uint64_t limit = ec->idle_ms > 0 ? (uint64_t)ec->idle_ms * 1000000u : 0;
    for (int i = 0; i < ec->max_conns; i++) {
        struct conn *c = &ec->slab[i];
        if (c->fd >= 0 && c->state != S_FREE && now - c->last_activity_ns >= limit) {
            conn_close(ec, c, C_TIMEOUT);
        }
    }
}

static void handle_signal(struct echod *ec)
{
    struct signalfd_siginfo si;
    while (read(ec->sigfd, &si, sizeof si) == sizeof si) {
        if (si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM) {
            ec->shutting_down = 1;
        }
    }
}

/* Graceful stop: stop accepting, flush pending output with a bounded write
 * attempt, close every conn, print stats. */
static void shutdown_all(struct echod *ec)
{
    arm_listener(ec, 0);
    for (int i = 0; i < ec->max_conns; i++) {
        struct conn *c = &ec->slab[i];
        if (c->fd >= 0 && c->state != S_FREE) {
            while (c->woff < c->wlen) {
                ssize_t n = write(c->fd, c->wbuf + c->woff, c->wlen - c->woff);
                if (n > 0) {
                    c->woff += (size_t)n;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK ||
                           errno == EPIPE || errno == ECONNRESET) {
                    break;
                } else if (errno != EINTR) {
                    break;
                }
            }
            conn_close(ec, c, C_SHUTDOWN);
        }
    }
    if (ec->stats) {
        stats_print(ec);
    }
}

static int parse_args(int argc, char **argv, struct echod *ec)
{
    memset(ec, 0, sizeof *ec);
    ec->family = 4;
    ec->idle_ms = 30000;
    ec->backlog = 16;
    ec->max_conns = 1024;
    ec->spare_fd = -1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if (strcmp(a, "-u") == 0) {
            ec->udp = 1;
        } else if (strcmp(a, "-4") == 0) {
            ec->family = 4;
        } else if (strcmp(a, "-6") == 0) {
            ec->family = 6;
        } else if (strcmp(a, "--no-accept") == 0) {
            ec->stop_accept = 1;
        } else if (strcmp(a, "--et") == 0) {
            ec->et = 1;
        } else if (strcmp(a, "--stats") == 0) {
            ec->stats = 1;
        } else if (strcmp(a, "--nodelay") == 0) {
            ec->nodelay = 1;
        } else if (strcmp(a, "--quickack") == 0) {
            ec->quickack = 1;
        } else if (strcmp(a, "--cork") == 0) {
            ec->cork = 1;
        } else if (strcmp(a, "--linger0") == 0) {
            ec->linger0 = 1;
        } else if (strcmp(a, "--keepalive") == 0) {
            ec->keepalive = 1;
        } else if ((v = nt_opt_value(a, 'p', &i, argc, argv)) != NULL) {
            char *end = NULL;
            long p = strtol(v, &end, 10);
            if (end == v || *end != '\0' || p < 0 || p > 65535) {
                return -1;
            }
            ec->port = (int)p;
        } else if (strcmp(a, "--port") == 0) {
            if (++i >= argc) {
                return -1;
            }
            char *end = NULL;
            long p = strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || p < 0 || p > 65535) {
                return -1;
            }
            ec->port = (int)p;
        } else if ((v = nt_opt_value(a, 'B', &i, argc, argv)) != NULL ||
                   (v = nt_opt_value(a, 'b', &i, argc, argv)) != NULL) {
            ec->backlog = (int)strtol(v, NULL, 10);
        } else if (strcmp(a, "--backlog") == 0) {
            if (++i >= argc) {
                return -1;
            }
            ec->backlog = (int)strtol(argv[i], NULL, 10);
        } else if ((v = nt_opt_value(a, 'M', &i, argc, argv)) != NULL) {
            ec->max_conns = (int)strtol(v, NULL, 10);
        } else if (strcmp(a, "--max-conns") == 0) {
            if (++i >= argc) {
                return -1;
            }
            ec->max_conns = (int)strtol(argv[i], NULL, 10);
        } else if (strcmp(a, "--idle") == 0) {
            if (++i >= argc) {
                return -1;
            }
            char *end = NULL;
            double sec = strtod(argv[i], &end);
            if (end == argv[i] || *end != '\0' || sec <= 0.0) {
                return -1;
            }
            ec->idle_ms = (int)(sec * 1000.0);
            if (ec->idle_ms < 1) {
                ec->idle_ms = 1;
            }
        } else if ((v = nt_opt_value(a, 'I', &i, argc, argv)) != NULL) {
            char *end = NULL;
            double sec = strtod(v, &end);
            if (end == v || *end != '\0' || sec <= 0.0) {
                return -1;
            }
            ec->idle_ms = (int)(sec * 1000.0);
            if (ec->idle_ms < 1) {
                ec->idle_ms = 1;
            }
        } else if (strcmp(a, "--bind") == 0) {
            if (++i >= argc) {
                return -1;
            }
            ec->bind_text = argv[i];
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "echod: unknown option '%s'\n", a);
            return -1;
        } else {
            return -1;
        }
    }
    if (ec->bind_text == NULL || ec->port < 0 || ec->max_conns < 1 ||
        ec->max_conns > 65536 || ec->backlog < 1) {
        return -1;
    }
    return 0;
}

static int open_listener(struct echod *ec)
{
    int fam = ec->family == 6 ? AF_INET6 : AF_INET;
    int type = ec->udp ? SOCK_DGRAM : SOCK_STREAM;
    int fd = socket(fam, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("echod: socket");
        return -1;
    }
    if (!ec->udp) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (ec->family == 6) {
            int off = 1; /* IPV6_V6ONLY explicit, spec table M2 */
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
        }
    }
    if (nt_guard_server_port((uint16_t)ec->port) != 0) {
        close(fd);
        return -1;
    }
    if (nt_guard_lab() != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    if (ec->family == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)ec->port);
        if (inet_pton(AF_INET6, ec->bind_text, &a->sin6_addr) != 1) {
            fprintf(stderr, "echod: '%s' is not a numeric IPv6 address\n", ec->bind_text);
            close(fd);
            return -1;
        }
        if (nt_guard_bind_v6(a->sin6_addr.s6_addr) != 0) {
            close(fd);
            return -1;
        }
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)ec->port);
        if (inet_pton(AF_INET, ec->bind_text, &a->sin_addr) != 1) {
            fprintf(stderr, "echod: '%s' is not a numeric IPv4 address\n", ec->bind_text);
            close(fd);
            return -1;
        }
        if (nt_guard_bind_v4(ntohl(a->sin_addr.s_addr)) != 0) {
            close(fd);
            return -1;
        }
        sl = sizeof *a;
    }
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0) {
        perror("echod: bind");
        close(fd);
        return -1;
    }
    if (!ec->udp && listen(fd, ec->backlog) != 0) {
        perror("echod: listen");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    struct echod ec;
    if (parse_args(argc, argv, &ec) != 0) {
        usage(stderr, argv[0]);
        return 2;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("echod: prctl");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);

    slab_init(&ec);

    ec.efd = epoll_create1(EPOLL_CLOEXEC);
    if (ec.efd < 0) {
        perror("echod: epoll_create1");
        return 2;
    }
    ec.lfd = open_listener(&ec);
    if (ec.lfd < 0) {
        return 2;
    }
    {
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = ec.lfd };
        if (ec.et) {
            ev.events |= EPOLLET;
        }
        if (epoll_ctl(ec.efd, EPOLL_CTL_ADD, ec.lfd, &ev) != 0) {
            perror("echod: epoll_ctl(listener add)");
            return 2;
        }
        if (!ec.udp) {
            ec.accepting = 1;
        }
    }

    ec.spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

    ec.tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ec.tfd >= 0) {
        struct itimerspec its;
        memset(&its, 0, sizeof its);
        its.it_interval.tv_sec = ec.idle_ms / 1000;
        its.it_interval.tv_nsec = (long)(ec.idle_ms % 1000) * 1000000L;
        its.it_value = its.it_interval;
        timerfd_settime(ec.tfd, 0, &its, NULL);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = ec.tfd };
        epoll_ctl(ec.efd, EPOLL_CTL_ADD, ec.tfd, &ev);
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
        perror("echod: sigprocmask");
        return 2;
    }
    ec.sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (ec.sigfd < 0) {
        perror("echod: signalfd");
        return 2;
    }
    struct epoll_event sev = { .events = EPOLLIN, .data.fd = ec.sigfd };
    epoll_ctl(ec.efd, EPOLL_CTL_ADD, ec.sigfd, &sev);

    fprintf(stderr, "echod: %s on %s:%d (max_conns=%d backlog=%d idle=%dms%s)\n",
            ec.udp ? "udp" : "tcp", ec.bind_text, ec.port, ec.max_conns,
            ec.backlog, ec.idle_ms, ec.et ? " et" : "");

    struct epoll_event evs[NT_MAXEV];
    while (!ec.shutting_down) {
        int n = epoll_wait(ec.efd, evs, NT_MAXEV, -1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("echod: epoll_wait");
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (ec.shutting_down) {
                break;
            }
            if (fd == ec.lfd) {
                if (ec.udp) {
                    udp_handle(&ec);
                } else {
                    accept_conns(&ec);
                }
            } else if (fd == ec.tfd) {
                timer_tick(&ec);
            } else if (fd == ec.sigfd) {
                handle_signal(&ec);
            } else {
                struct conn *c = conn_by_fd(&ec, fd);
                if (c == NULL) {
                    continue;
                }
                if (evs[i].events & EPOLLERR) {
                    int soerr = 0;
                    socklen_t sl = sizeof soerr;
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
                    if (soerr == ECONNRESET) {
                        conn_close(&ec, c, C_RST);
                    } else {
                        conn_close(&ec, c, C_ERROR);
                    }
                    continue;
                }
                if (evs[i].events & (EPOLLIN | EPOLLHUP)) {
                    if (c->state == S_HANDLING || c->state == S_CLOSING) {
                        conn_read(&ec, c);
                    }
                    if (c->state == S_FREE) {
                        continue; /* conn_read closed it */
                    }
                }
                if (evs[i].events & EPOLLOUT) {
                    conn_write(&ec, c);
                }
            }
        }
    }

    shutdown_all(&ec);
    close(ec.sigfd);
    if (ec.tfd >= 0) {
        close(ec.tfd);
    }
    if (ec.spare_fd >= 0) {
        close(ec.spare_fd);
    }
    if (ec.lfd >= 0) {
        close(ec.lfd);
    }
    close(ec.efd);
    free(ec.slab);
    return 0;
}