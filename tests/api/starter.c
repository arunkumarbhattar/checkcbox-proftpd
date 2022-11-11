//
// Created by twinturbo on 11/10/22.
//
#include <checkcbox_extensions.h>
#include "tests.h"
#include <stdlib.h>
static pool *p = NULL;
static int xfer_bufsz = -1;

static int tmp_fd = -1;
static const char *tmp_path = NULL;
/* Telnet "Interpret As Command" indicator */
#define TELNET_IAC     255
#define TELNET_DONT    254
#define TELNET_DO      253
#define TELNET_WONT    252
#define TELNET_WILL    251
#define TELNET_IP      244
#define TELNET_DM      242

static void test_cleanup(void) {
    (void) close(tmp_fd);
    tmp_fd = -1;

    if (tmp_path != NULL) {
        (void) unlink(tmp_path);
        tmp_path = NULL;
    }

    pr_unregister_netio(PR_NETIO_STRM_CTRL|PR_NETIO_STRM_DATA|PR_NETIO_STRM_OTHR);
}
static void set_up(void) {
    if (p == NULL) {
        p = permanent_pool = make_sub_pool(NULL);
    }

    init_netio();
    xfer_bufsz = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_RD);

    if (getenv("TEST_VERBOSE") != NULL) {
        pr_trace_set_levels("netio", 1, 20);
    }
}


static int open_tmpfile(void) {
    int fd;

    if (tmp_path != NULL) {
        test_cleanup();
    }

    tmp_path = "/tmp/netio-test.dat";
    fd = open(tmp_path, O_RDWR|O_CREAT, 0666);
   // ck_assert_msg(fd >= 0, "Failed to open '%s': %s", tmp_path, strerror(errno));
    tmp_fd = fd;

    return fd;
}

int main() {
    set_up();
    _TPtr<char> buf = string_tainted_malloc(10);
    _TPtr<char> res = NULL;
    char *cmd;
    char telnet_opt;
    pr_netio_stream_t *in, *out;
    pr_buffer_t *pbuf;
    int len, xerrno;

    in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
    out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

    pr_netio_buffer_alloc(in);
    pbuf = in->strm_buf;

    telnet_opt = 7;
    len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c%c%cWorld!\n",
                   TELNET_IAC, TELNET_IAC, TELNET_WILL, telnet_opt);
    pbuf->remaining = pbuf->buflen - len;
    pbuf->current = pbuf->buf;

    buf[sizeof(buf)-1] = '\0';

    res = pr_netio_telnet_gets(buf, 10-1, in, out);
    xerrno = errno;

    ck_assert_msg(res == NULL, "Expected null");
    ck_assert_msg(xerrno == E2BIG, "Failed to set errno to E2BIG, got %s (%d)",
                  strerror(xerrno), xerrno);

    pr_netio_close(in);
    pr_netio_close(out);
}