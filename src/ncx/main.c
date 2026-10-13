/*
 * ncx: numeric netcat -- a TCP/UDP byte pump with explicit lab guards.
 *
 *   ncx [-l] [-u] [-4|-6] [-s addr] [-p port] [-w sec] [-N] [-v] HOST PORT
 *   ncx -l [-u] [-4|-6] [-s addr] [-p port] [-w sec] [-N]
 *
 * Deliberately small and legible: two directions of one byte stream (TCP) or
 * one message stream (UDP), driven by a single poll(2) loop with bounded
 * buffers. No threads, no name resolution, no exec. Every byte the peer sends
 * is treated as untrusted data.
 *
 * Exit codes (see docs/phase4.md):
 *   0 ok · 1 usage/bind · 2 connect · 3 write error (EPIPE/ECONNRESET)
 *   4 timeout (-w) · 5 peer closed before any data was exchanged
 */
#include "nettk.h"
#include "guard.h"
#include "clock.h"
#include "opts.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NT_IOSZ 65536

enum {
    RC_OK = 0,
    RC_USAGE = 1,
    RC_CONNECT = 2,
    RC_WRITE = 3,
    RC_TIMEOUT = 4,
    RC_PEERCLOSED = 5,
};

struct opts {
    int listen;
    int udp;
    int family;        /* 4 or 6 */
    const char *src;   /* -s bind source */
    const char *host;  /* connect target */
    int srcport;       /* -p: local bind port (listen, or connect source); -1 unset */
    int dstport;       /* positional destination port; -1 unset */
    int timeout_ms;    /* -w, 0 = none */
    int do_shutdown;   /* -N */
    int verbose;
    int linger0, nodelay, quickack, cork;
};

struct tx {
    uint8_t buf[NT_IOSZ];
    size_t len, off;
};

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s [-l] [-u] [-4|-6] [-s addr] [-p port] [-w sec] [-N] [-v]\n"
            "           [--linger0] [--nodelay] [--quickack] [--cork] HOST PORT\n"
            "       %s -l [-u] [-4|-6] [-s addr] [-p port] [-w sec] [-N] [-v]\n"
            "  TCP by default, -u UDP; -l listens (TCP: one accepted conn)\n"
            "  numeric addresses only; never runs anything\n",
            prog, prog);
}

static int parse_port(const char *v, int *out)
{
    char *end = NULL;
    long p = strtol(v, &end, 10);
    if (end == v || *end != '\0' || p < 0 || p > 65535) {
        return -1;
    }
    *out = (int)p;
    return 0;
}

static int parse_args(int argc, char **argv, struct opts *o)
{
    memset(o, 0, sizeof *o);
    o->family = 4;
    o->srcport = -1;
    o->dstport = -1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if (strcmp(a, "-l") == 0) {
            o->listen = 1;
        } else if (strcmp(a, "-u") == 0) {
            o->udp = 1;
        } else if (strcmp(a, "-4") == 0) {
            o->family = 4;
        } else if (strcmp(a, "-6") == 0) {
            o->family = 6;
        } else if (strcmp(a, "-N") == 0) {
            o->do_shutdown = 1;
        } else if (strcmp(a, "-v") == 0) {
            o->verbose = 1;
        } else if (strcmp(a, "--linger0") == 0) {
            o->linger0 = 1;
        } else if (strcmp(a, "--nodelay") == 0) {
            o->nodelay = 1;
        } else if (strcmp(a, "--quickack") == 0) {
            o->quickack = 1;
        } else if (strcmp(a, "--cork") == 0) {
            o->cork = 1;
        } else if (a[0] == '-' && a[1] != '\0' &&
                   (v = nt_opt_value(a, 's', &i, argc, argv)) != NULL) {
            o->src = v;
        } else if (a[0] == '-' && a[1] != '\0' &&
                   (v = nt_opt_value(a, 'p', &i, argc, argv)) != NULL) {
            if (parse_port(v, &o->srcport) != 0) {
                return -1;
            }
        } else if (a[0] == '-' && a[1] != '\0' &&
                   (v = nt_opt_value(a, 'w', &i, argc, argv)) != NULL) {
            char *end = NULL;
            double sec = strtod(v, &end);
            if (end == v || *end != '\0' || sec < 0.0) {
                return -1;
            }
            o->timeout_ms = (int)(sec * 1000.0);
            if (o->timeout_ms < 0) {
                o->timeout_ms = 0;
            }
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "ncx: unknown option '%s'\n", a);
            return -1;
        } else if (o->host == NULL) {
            o->host = a;
        } else if (o->dstport < 0) {
            if (parse_port(a, &o->dstport) != 0) {
                return -1;
            }
        } else {
            fprintf(stderr, "ncx: too many positional arguments\n");
            return -1;
        }
    }
    return 0;
}

static int set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int set_reuse(int fd)
{
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
}

static int mkaddr(int family, const char *text, uint16_t port,
                  struct sockaddr_storage *ss, socklen_t *len)
{
    memset(ss, 0, sizeof *ss);
    if (family == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        if (inet_pton(AF_INET, text, &sin->sin_addr) != 1) {
            return -1;
        }
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        *len = sizeof *sin;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        if (inet_pton(AF_INET6, text, &sin6->sin6_addr) != 1) {
            return -1;
        }
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        *len = sizeof *sin6;
    }
    return 0;
}

/* Refuse a local port below 1024 unless it is 0 (ephemeral). */
static int guard_local_port(int port)
{
    if (port == 0) {
        return 0;
    }
    return nt_guard_server_port((uint16_t)port);
}

/* Apply the exercise options to a TCP socket (linger is applied at close). */
static void apply_tcp_opts(const struct opts *o, int fd)
{
    int one = 1;
    if (o->nodelay) {
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    if (o->quickack) {
        setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof one);
    }
    if (o->cork) {
        setsockopt(fd, IPPROTO_TCP, TCP_CORK, &one, sizeof one);
    }
}

static int make_socket(const struct opts *o)
{
    int type = o->udp ? SOCK_DGRAM : SOCK_STREAM;
    int fam = o->family == 6 ? AF_INET6 : AF_INET;
    int fd = socket(fam, type | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("ncx: socket");
    }
    return fd;
}

/* Bind the local end: -s address and/or -p port (connect mode source). */
static int bind_local(const struct opts *o, int fd)
{
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    const int port = o->srcport < 0 ? 0 : o->srcport;
    if (o->family == 6) {
        struct sockaddr_in6 *b = (struct sockaddr_in6 *)&ss;
        memset(b, 0, sizeof *b);
        b->sin6_family = AF_INET6;
        b->sin6_port = htons((uint16_t)port);
        sl = sizeof *b;
        if (o->src != NULL) {
            if (inet_pton(AF_INET6, o->src, &b->sin6_addr) != 1) {
                fprintf(stderr, "ncx: '%s' is not a numeric IPv6 address\n", o->src);
                return -1;
            }
            if (nt_guard_bind_v6(b->sin6_addr.s6_addr) != 0) {
                return -1;
            }
        }
        if (port > 0 && guard_local_port(port) != 0) {
            return -1;
        }
        if (bind(fd, (struct sockaddr *)b, sl) != 0) {
            perror("ncx: bind");
            return -1;
        }
        return 0;
    }
    struct sockaddr_in *b = (struct sockaddr_in *)&ss;
    memset(b, 0, sizeof *b);
    b->sin_family = AF_INET;
    b->sin_port = htons((uint16_t)port);
    sl = sizeof *b;
    if (o->src != NULL) {
        if (inet_pton(AF_INET, o->src, &b->sin_addr) != 1) {
            fprintf(stderr, "ncx: '%s' is not a numeric IPv4 address\n", o->src);
            return -1;
        }
        if (nt_guard_bind_v4(ntohl(b->sin_addr.s_addr)) != 0) {
            return -1;
        }
    } else {
        b->sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (port > 0 && guard_local_port(port) != 0) {
        return -1;
    }
    if (bind(fd, (struct sockaddr *)b, sl) != 0) {
        perror("ncx: bind");
        return -1;
    }
    return 0;
}

/* Nonblocking connect with a poll deadline. Returns 0 or an RC_ code. */
static int conn_wait(int fd, const struct opts *o, uint64_t deadline)
{
    for (;;) {
        int64_t rem = o->timeout_ms > 0 ? (int64_t)deadline - (int64_t)nt_now_ns() : -1;
        if (rem <= 0 && o->timeout_ms > 0) {
            return RC_TIMEOUT;
        }
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        int r = poll(&p, 1, o->timeout_ms > 0 ? (int)(rem / 1000000) : -1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ncx: poll");
            return RC_CONNECT;
        }
        if (r == 0) {
            return RC_TIMEOUT;
        }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0) {
            perror("ncx: getsockopt");
            return RC_CONNECT;
        }
        if (soerr != 0) {
            errno = soerr;
            fprintf(stderr, "ncx: connect: %s\n", strerror(soerr));
            return RC_CONNECT;
        }
        return 0;
    }
}

/* Wait for the listener to have a pending connection.
 * Returns the accepted fd, -2 on timeout, -1 on error. */
static int accept_wait(int lfd, int timeout_ms, uint64_t deadline)
{
    for (;;) {
        int64_t rem = timeout_ms > 0 ? (int64_t)deadline - (int64_t)nt_now_ns() : -1;
        if (rem <= 0 && timeout_ms > 0) {
            return -2;
        }
        struct pollfd p = { .fd = lfd, .events = POLLIN };
        int r = poll(&p, 1, timeout_ms > 0 ? (int)(rem / 1000000) : -1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ncx: poll(accept)");
            return -1;
        }
        if (r == 0) {
            return -2;
        }
        int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (fd >= 0) {
            return fd;
        }
        if (errno == EINTR || errno == EAGAIN) {
            continue; /* level-triggered: spurts happen, retry */
        }
        perror("ncx: accept");
        return -1;
    }
}

enum { CAUSE_OK = 0, CAUSE_RST = 1, CAUSE_TIMEOUT = 2, CAUSE_WRITE = 3 };

static const char *cause_name(int c)
{
    switch (c) {
    case CAUSE_OK:      return "normal close";
    case CAUSE_RST:     return "reset (RST)";
    case CAUSE_TIMEOUT: return "timeout";
    case CAUSE_WRITE:   return "stdout write error";
    default:            return "?";
    }
}

static int pump_tcp(int sock, const struct opts *o, uint64_t deadline)
{
    struct tx tin = { 0 }, tout = { 0 };
    int stdin_eof = 0, sock_eof = 0, shutdown_done = 0;
    uint64_t sent = 0, received = 0;
    int cause = CAUSE_OK;

    for (;;) {
        int want_stdin = !stdin_eof && tin.len < NT_IOSZ;
        int want_rsock = !sock_eof && tout.len < NT_IOSZ;
        int want_wsock = tin.len > 0;
        int want_stdout = tout.len > 0;

        struct pollfd pf[3];
        pf[0] = (struct pollfd){ .fd = want_stdin ? 0 : -1, .events = POLLIN };
        pf[1] = (struct pollfd){ .fd = sock,
                                 .events = (short)((want_rsock ? POLLIN : 0) |
                                                   (want_wsock ? POLLOUT : 0)) };
        pf[2] = (struct pollfd){ .fd = want_stdout ? 1 : -1, .events = POLLOUT };

        int64_t rem = o->timeout_ms > 0 ? (int64_t)deadline - (int64_t)nt_now_ns() : -1;
        if (rem <= 0 && o->timeout_ms > 0) {
            cause = CAUSE_TIMEOUT;
            break;
        }
        int r = poll(pf, 3, o->timeout_ms > 0 ? (int)(rem / 1000000) : -1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ncx: poll");
            cause = CAUSE_WRITE;
            break;
        }
        if (r == 0 && o->timeout_ms > 0) {
            cause = CAUSE_TIMEOUT;
            break;
        }

        if (pf[0].fd >= 0 && (pf[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(0, tin.buf + tin.len, NT_IOSZ - tin.len);
            if (n > 0) {
                tin.len += (size_t)n;
            } else if (n == 0) {
                /* EOF on stdin: remember it, but never call shutdown before the
                 * bytes already read are on the wire -- a SHUT_WR socket makes
                 * the next write() fail with EPIPE. */
                stdin_eof = 1;
            } else if (errno != EINTR && errno != EAGAIN) {
                cause = CAUSE_WRITE;
                break;
            }
        }

        if (pf[1].revents & POLLERR) {
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &sl);
            if (soerr == ECONNRESET || soerr == EPIPE) {
                cause = CAUSE_RST;
            }
            /* fall through to the read path: recv() turns a reset into
             * ECONNRESET and a clean close into EOF. */
        }
        /* POLLIN|POLLHUP arrive TOGETHER when data and FIN coalesce. HUP alone
         * does not mean "nothing left to read": drain until EAGAIN or EOF, or
         * buffered data is silently thrown away. */
        if ((pf[1].revents & (POLLIN | POLLHUP)) && !sock_eof) {
            for (;;) {
                if (tout.len >= NT_IOSZ) {
                    break; /* output full: backpressure to the peer */
                }
                ssize_t n = read(sock, tout.buf + tout.len, NT_IOSZ - tout.len);
                if (n > 0) {
                    tout.len += (size_t)n;
                    received += (uint64_t)n;
                } else if (n == 0) {
                    sock_eof = 1;
                    break;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else if (errno == EINTR) {
                    continue;
                } else if (errno == ECONNRESET) {
                    cause = CAUSE_RST;
                    sock_eof = 1;
                    break;
                } else {
                    cause = CAUSE_WRITE;
                    break;
                }
            }
        }

        if ((pf[1].revents & POLLOUT) && tin.len > 0) {
            ssize_t n = write(sock, tin.buf + tin.off, tin.len - tin.off);
            if (n > 0) {
                tin.off += (size_t)n;
                if (tin.off == tin.len) {
                    tin.len = tin.off = 0;
                }
                sent += (uint64_t)n;
            } else if (n < 0 && errno == EPIPE) {
                cause = CAUSE_RST;
                sock_eof = 1;
            } else if (n < 0 && errno != EINTR && errno != EAGAIN &&
                       errno != ECONNRESET) {
                perror("ncx: write");
                cause = CAUSE_WRITE;
                break;
            }
        }

        if (pf[2].fd >= 0 && (pf[2].revents & POLLOUT) && tout.len > 0) {
            ssize_t n = write(1, tout.buf + tout.off, tout.len - tout.off);
            if (n > 0) {
                tout.off += (size_t)n;
                if (tout.off == tout.len) {
                    tout.len = tout.off = 0;
                }
            } else if (n < 0 && errno != EINTR && errno != EAGAIN) {
                perror("ncx: write(stdout)");
                cause = CAUSE_WRITE;
                break;
            }
        }

        if (sock_eof && tout.len == 0) {
            /* The connection is gone; any stdin bytes we could not push to it
             * are gone with it (that is what a reset means). Stop pumping. */
            break;
        }

        /* -N: once stdin is drained, half-close the socket so the peer sees
         * EOF while we keep reading its reply. */
        if (o->do_shutdown && stdin_eof && !shutdown_done && tin.len == 0) {
            if (shutdown(sock, SHUT_WR) == 0) {
                shutdown_done = 1;
            }
        }
    }

    if (o->verbose) {
        fprintf(stderr, "ncx: sent=%llu recv=%llu cause=%s\n",
                (unsigned long long)sent, (unsigned long long)received,
                cause_name(cause));
    }
    if (cause != CAUSE_OK) {
        return cause == CAUSE_TIMEOUT ? RC_TIMEOUT : RC_WRITE;
    }
    if (sent == 0 && received == 0 && cause == CAUSE_OK && sock_eof) {
        return RC_PEERCLOSED;
    }
    return RC_OK;
}

static int pump_udp(int fd, const struct opts *o, uint64_t deadline)
{
    uint64_t sent = 0, received = 0;
    int cause = CAUSE_OK;
    for (;;) {
        struct pollfd pf[2];
        pf[0] = (struct pollfd){ .fd = 0, .events = POLLIN };
        pf[1] = (struct pollfd){ .fd = fd, .events = POLLIN };
        int64_t rem = o->timeout_ms > 0 ? (int64_t)deadline - (int64_t)nt_now_ns() : -1;
        if (rem <= 0 && o->timeout_ms > 0) {
            cause = CAUSE_TIMEOUT;
            break;
        }
        int r = poll(pf, 2, o->timeout_ms > 0 ? (int)(rem / 1000000) : -1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ncx: poll");
            cause = CAUSE_WRITE;
            break;
        }
        if (r == 0 && o->timeout_ms > 0) {
            cause = CAUSE_TIMEOUT;
            break;
        }
        if (pf[0].revents & (POLLIN | POLLHUP)) {
            uint8_t buf[65507];
            ssize_t n = read(0, buf, sizeof buf);
            if (n > 0) {
                if (send(fd, buf, (size_t)n, MSG_NOSIGNAL) < 0) {
                    if (errno == ECONNREFUSED) {
                        fprintf(stderr, "ncx: send: %s (ICMP port unreachable)\n",
                                strerror(errno));
                        cause = CAUSE_RST;
                        break;
                    }
                    if (errno != EINTR) {
                        perror("ncx: send");
                        cause = CAUSE_RST;
                        break;
                    }
                } else {
                    sent += (uint64_t)n;
                }
            } else if (n == 0) {
                break; /* stdin EOF ends a datagram relay */
            } else if (errno != EINTR && errno != EAGAIN) {
                cause = CAUSE_WRITE;
                break;
            }
        }
        if (pf[1].revents & (POLLIN | POLLERR | POLLHUP)) {
            uint8_t buf[NT_IOSZ];
            ssize_t n = recv(fd, buf, sizeof buf, 0);
            if (n > 0) {
                received += (uint64_t)n;
                if (write(1, buf, (size_t)n) < 0 && errno != EINTR) {
                    perror("ncx: write(stdout)");
                    cause = CAUSE_WRITE;
                    break;
                }
            } else if (n < 0 && errno == ECONNREFUSED) {
                fprintf(stderr, "ncx: recv: %s (ICMP port unreachable)\n",
                        strerror(errno));
                cause = CAUSE_RST;
                break;
            } else if (n < 0 && errno != EINTR && errno != EAGAIN) {
                perror("ncx: recv");
                cause = CAUSE_RST;
                break;
            }
        }
    }
    if (o->verbose) {
        fprintf(stderr, "ncx: sent=%llu recv=%llu cause=%s\n",
                (unsigned long long)sent, (unsigned long long)received,
                cause_name(cause));
    }
    if (cause != CAUSE_OK) {
        return cause == CAUSE_TIMEOUT ? RC_TIMEOUT : (cause == CAUSE_WRITE ? RC_WRITE : RC_WRITE);
    }
    return RC_OK;
}

static int listen_tcp(const struct opts *o)
{
    int fd = make_socket(o);
    if (fd < 0) {
        return RC_USAGE;
    }
    set_reuse(fd);
    if (bind_local(o, fd) != 0) {
        close(fd);
        return RC_USAGE;
    }
    if (listen(fd, 1) != 0) {
        perror("ncx: listen");
        close(fd);
        return RC_USAGE;
    }
    if (o->verbose || o->srcport < 0) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) {
            char host[INET6_ADDRSTRLEN] = "?";
            uint16_t port = 0;
            if (ss.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                inet_ntop(AF_INET, &sin->sin_addr, host, sizeof host);
                port = ntohs(sin->sin_port);
            } else {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof host);
                port = ntohs(sin6->sin6_port);
            }
            fprintf(stderr, "ncx: listening on %s:%u\n", host, port);
        }
    }
    uint64_t deadline = o->timeout_ms > 0 ? nt_now_ns() + nt_ms_to_ns((uint64_t)o->timeout_ms) : 0;
    int sock = accept_wait(fd, o->timeout_ms, deadline);
    close(fd);
    if (sock == -2) {
        return RC_TIMEOUT;
    }
    if (sock < 0) {
        return RC_USAGE;
    }
    set_nb(sock);
    apply_tcp_opts(o, sock);
    int rc = pump_tcp(sock, o, deadline);
    if (o->linger0) {
        struct linger lg = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    }
    close(sock);
    return rc;
}

static int listen_udp(const struct opts *o)
{
    int fd = make_socket(o);
    if (fd < 0) {
        return RC_USAGE;
    }
    if (bind_local(o, fd) != 0) {
        close(fd);
        return RC_USAGE;
    }
    uint64_t deadline = o->timeout_ms > 0 ? nt_now_ns() + nt_ms_to_ns((uint64_t)o->timeout_ms) : 0;
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    int rc = RC_OK;
    for (;;) {
        int64_t rem = o->timeout_ms > 0 ? (int64_t)deadline - (int64_t)nt_now_ns() : -1;
        if (rem <= 0 && o->timeout_ms > 0) {
            rc = RC_TIMEOUT;
            break;
        }
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, o->timeout_ms > 0 ? (int)(rem / 1000000) : -1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ncx: poll");
            rc = RC_USAGE;
            break;
        }
        if (r == 0 && o->timeout_ms > 0) {
            rc = RC_TIMEOUT;
            break;
        }
        uint8_t buf[NT_IOSZ];
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            perror("ncx: recvfrom");
            rc = RC_USAGE;
            break;
        }
        if (o->verbose) {
            char host[INET6_ADDRSTRLEN] = "?";
            uint16_t port = 0;
            if (peer.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&peer;
                inet_ntop(AF_INET, &sin->sin_addr, host, sizeof host);
                port = ntohs(sin->sin_port);
            } else {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&peer;
                inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof host);
                port = ntohs(sin6->sin6_port);
            }
            fprintf(stderr, "ncx: first datagram from %s:%u\n", host, port);
        }
        if (write(1, buf, (size_t)n) < 0 && errno != EINTR) {
            perror("ncx: write(stdout)");
            rc = RC_WRITE;
            break;
        }
        if (connect(fd, (struct sockaddr *)&peer, plen) != 0) {
            perror("ncx: connect(udp peer)");
            rc = RC_USAGE;
            break;
        }
        rc = pump_udp(fd, o, deadline);
        break;
    }
    close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    struct opts o;
    if (parse_args(argc, argv, &o) != 0) {
        usage(stderr, argv[0]);
        return RC_USAGE;
    }

    signal(SIGPIPE, SIG_IGN);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("ncx: prctl");
        return RC_USAGE;
    }

    int rc;
    if (o.listen) {
        if (o.udp) {
            rc = listen_udp(&o);
        } else {
            rc = listen_tcp(&o);
        }
        return rc;
    }

    if (o.host == NULL || o.dstport < 0) {
        usage(stderr, argv[0]);
        return RC_USAGE;
    }
    if (nt_guard_lab() != 0) {
        return RC_USAGE;
    }

    int fd = make_socket(&o);
    if (fd < 0) {
        return RC_USAGE;
    }

    if (o.src != NULL || o.srcport >= 0) { /* -s and/or source port in connect mode */
        if (bind_local(&o, fd) != 0) {
            close(fd);
            return RC_USAGE;
        }
    }

    struct sockaddr_storage ss;
    socklen_t sl = 0;
    if (o.family == 6) {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        if (inet_pton(AF_INET6, o.host, &a.sin6_addr) != 1) {
            fprintf(stderr, "ncx: '%s' is not a numeric IPv6 address\n", o.host);
            close(fd);
            return RC_USAGE;
        }
        if (nt_guard_peer_v6(a.sin6_addr.s6_addr) != 0) {
            close(fd);
            return RC_USAGE;
        }
        a.sin6_family = AF_INET6;
        a.sin6_port = htons((uint16_t)o.dstport);
        ss = *(struct sockaddr_storage *)&a;
        sl = sizeof a;
    } else {
        if (mkaddr(4, o.host, (uint16_t)o.dstport, &ss, &sl) != 0) {
            fprintf(stderr, "ncx: '%s' is not a numeric IPv4 address\n", o.host);
            close(fd);
            return RC_USAGE;
        }
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&ss;
        if (nt_guard_peer_v4(ntohl(sin->sin_addr.s_addr)) != 0) {
            close(fd);
            return RC_USAGE;
        }
    }

    uint64_t deadline = o.timeout_ms > 0 ? nt_now_ns() + nt_ms_to_ns((uint64_t)o.timeout_ms) : 0;

    if (o.udp) {
        if (connect(fd, (struct sockaddr *)&ss, sl) != 0) {
            perror("ncx: connect");
            close(fd);
            return RC_CONNECT;
        }
        rc = pump_udp(fd, &o, deadline);
        close(fd);
        return rc;
    }

    if (set_nb(fd) != 0) {
        perror("ncx: fcntl");
        close(fd);
        return RC_CONNECT;
    }
    int cr = connect(fd, (struct sockaddr *)&ss, sl);
    if (cr != 0 && errno != EINPROGRESS) {
        fprintf(stderr, "ncx: connect: %s\n", strerror(errno));
        close(fd);
        return RC_CONNECT;
    }
    if (cr != 0) {
        int wr = conn_wait(fd, &o, deadline);
        if (wr != 0) {
            if (wr == RC_TIMEOUT) {
                fprintf(stderr, "ncx: connect: timed out\n");
            }
            close(fd);
            return wr;
        }
    }
    apply_tcp_opts(&o, fd);
    rc = pump_tcp(fd, &o, deadline);
    if (o.linger0) {
        struct linger lg = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    }
    close(fd);
    return rc;
}