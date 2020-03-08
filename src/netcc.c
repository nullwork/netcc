#include "program.h"
#include "vault/vault.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define DBPATH "vault.db"

#define HTTPMAXHDR (1 << 12)
#define HTTPMAXBODY (1 << 13)
#define HTTPTIMEOUT 10
#define HTTPADDR "127.0.0.1"
#define HTTPPORT 3000

// Request path max length, this is arbitrary.
#define REQPATHMAX 21

#define PGMHDRSZ offsetof(struct pgmres, buf)

#pragma pack(push, 1)
struct pgmres
{
    int status;
    uint32_t srcsz;
    uint32_t cmpsz;
    uint32_t pgmsz;
    char buf[PGMMAXOUT*3];
};
#pragma pack(pop)

struct netcc
{
    struct event_base *evbase;
    struct evhttp *http;
    struct db *db;

    // Templates
    // TODO: Clean this up.
    void *page_form;
    size_t pf_sz;

    void *page_dsp;
    size_t pd_sz;
};

static void on_request(struct evhttp_request *req, void *arg);
static void on_signal(evutil_socket_t fd, short event, void *arg);

static int load_files(struct netcc *n);
static void unload_files(struct netcc *n);
static inline void *map_file(const char *path, size_t *sz);

int main(int argc, char *argv[])
{
    UNUSED(argc);
    UNUSED(argv);

    struct netcc netcc;
    struct db *db = db_open(DBPATH);
    if (!db) {
        fprintf(stderr, "FATAL: Could not open database: %s\n", DBPATH);
        return -1;
    }

    if (load_files(&netcc) < 0) {
        fprintf(stderr, "FATAL: Template files not found.\n");
        db_close(db);
        return -1;
    }

    struct event_base *evbase = event_base_new();
    struct evhttp *http = evhttp_new(evbase);

    evhttp_set_allowed_methods(http, EVHTTP_REQ_GET|EVHTTP_REQ_POST);
    evhttp_set_max_headers_size(http, HTTPMAXHDR);
    evhttp_set_max_body_size(http, HTTPMAXBODY);
    evhttp_set_timeout(http, HTTPTIMEOUT);
    evhttp_set_gencb(http, on_request, &netcc);
    struct event *sigev = evsignal_new(evbase, SIGINT, on_signal, evbase);
    event_add(sigev, NULL);

    if (evhttp_bind_socket(http, HTTPADDR, HTTPPORT)) {
        evhttp_free(http);
        event_base_free(evbase);
        unload_files(&netcc);
        db_close(db);
        fprintf(stderr, "FATAL: Could not bind the server socket\n");
        return -1;
    }

    netcc.evbase = evbase;
    netcc.http = http;
    netcc.db = db;

    event_base_dispatch(evbase);

    event_del(sigev);
    evhttp_free(http);
    event_base_free(evbase);
    unload_files(&netcc);
    db_close(db);
    return 0;
}

static void on_request(struct evhttp_request *req, void *arg)
{
    struct netcc *netcc = arg;
    if (!req)
        return;

    enum evhttp_cmd_type type = evhttp_request_get_command(req);
    if (type == EVHTTP_REQ_GET) {
        struct evbuffer *buf = evhttp_request_get_input_buffer(req);
        evbuffer_drain(buf, evbuffer_get_length(buf));

        struct evhttp_uri *uri = evhttp_uri_parse(evhttp_request_get_uri(req));
        if (!uri) {
            evhttp_send_error(req, HTTP_BADREQUEST, NULL);
            return;
        }
        const char *path = evhttp_uri_get_path(uri);
        size_t plen = strlen(path);
        if (plen == 0 || plen > REQPATHMAX) {
            evhttp_uri_free(uri);
            evhttp_send_error(req, HTTP_BADREQUEST, NULL);
            return;
        }
        if (plen == 1 && path[0] == '/') {
            // Send out the html page template
            evbuffer_add(buf, netcc->page_form, netcc->pf_sz);
            evhttp_send_reply(req, HTTP_OK, "OK", buf);
        } else if (plen == 11 && strncmp(path, "/api/", 5) == 0) {
            uint32_t sz;
            void *data = db_get(netcc->db, path+5, 6, &sz);
            if (data) {
                struct pgmres *res = data;
                evbuffer_add_printf(buf, "%d\n%u\n%u\n%u\n", res->status, res->srcsz, res->cmpsz, res->pgmsz);
                evbuffer_add(buf, res->buf, res->srcsz+res->cmpsz+res->pgmsz);
                free(data);
                evhttp_send_reply(req, HTTP_OK, "OK", buf);
            } else {
                evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", NULL);
            }
        } else {
            evbuffer_add(buf, netcc->page_dsp, netcc->pd_sz);
            evhttp_send_reply(req, HTTP_OK, "OK", buf);
        }

        evhttp_uri_free(uri);
        return;
    } else if (type == EVHTTP_REQ_POST) {
        struct evhttp_uri *uri = evhttp_uri_parse(evhttp_request_get_uri(req));
        if (!uri) {
            evhttp_send_error(req, HTTP_BADREQUEST, NULL);
            return;
        }
        const char *path = evhttp_uri_get_path(uri);
        if (strlen(path) != 1) {
            evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", NULL);
            evhttp_uri_free(uri);
            return;
        }

        struct evbuffer *buf = evhttp_request_get_input_buffer(req);
        struct pgmres pgm = { .srcsz = 0, .cmpsz = 0, .pgmsz = 0 };
        pgm.srcsz = (uint32_t)evbuffer_get_length(buf);
        evbuffer_remove(buf, pgm.buf, pgm.srcsz);

        char pathin[11] = "tmp/XXXXXX";
        char pathout[15] = "tmp/XXXXXX.out";
        char key[6] = "XXXXXX";
        int fd = mkstemp(pathin);
        if (fd < 0) {
            evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", NULL);
            return;
        }
        memcpy(key, pathin+4, 6); // NOLINT
        memcpy(pathout+4, key, 6);  // NOLINT
        ssize_t n = write(fd, pgm.buf, pgm.srcsz);
        if (n < 0 || (size_t)n != pgm.srcsz) {
            evhttp_uri_free(uri);
            evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", NULL);
            return;
        }

        int status = compile_program(pathin, pathout, pgm.buf+pgm.srcsz, &pgm.cmpsz, 5);
        remove(pathin);
        if (status == CMPINTERR) {
            // TODO: Better error reporting. (LOG THIS)
            remove(pathout);
            evhttp_uri_free(uri);
            evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", NULL);
            return;
        } else if (status == CMPOK) {
            status = run_program(pathout, pgm.buf+pgm.srcsz+pgm.cmpsz, &pgm.pgmsz, 5);
            if (status == PGMINTERR) {
                // TODO: Better error reporting. (LOG THIS)
                remove(pathout);
                evhttp_uri_free(uri);
                evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", NULL);
                return;
            }
        }
        remove(pathout);
        evhttp_uri_free(uri);

        // Add the result to the database.
        pgm.status = status;
        if (db_insert(netcc->db, key, 6, &pgm, PGMHDRSZ + pgm.srcsz + pgm.cmpsz + pgm.pgmsz) != DBOK) {
            evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", NULL);
            return;
        }

        evbuffer_add_printf(buf, "http://localhost:3000/%.*s", 6, key);
        evhttp_send_reply(req, HTTP_OK, "OK", buf);
    } else {
        evhttp_send_reply(req, HTTP_NOTIMPLEMENTED, "Not Implemented", NULL);
    }
}

static void on_signal(evutil_socket_t fd, short event, void *arg)
{
    UNUSED(fd);
    UNUSED(event);
    event_base_loopbreak(arg);
}

static int load_files(struct netcc *n)
{
    size_t pf_sz;
    void *page_form = map_file("pub/index.html", &pf_sz);
    if (!page_form)
        return -1;
    size_t pd_sz;
    void *page_dsp = map_file("pub/display.html", &pd_sz);
    if (!page_dsp) {
        munmap(page_form, pf_sz);
    }
    n->pf_sz = pf_sz;
    n->page_form = page_form;
    n->pd_sz = pd_sz; // NOLINT [FP]
    n->page_dsp = page_dsp;
    return 0;
}

static void unload_files(struct netcc *n)
{
    munmap(n->page_form, n->pf_sz);
    munmap(n->page_dsp, n->pd_sz);
}

static inline void *map_file(const char *path, size_t *sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat fs;
    if (fstat(fd, &fs) < 0) {
        close(fd);
        return NULL;
    }
    void *map = mmap(NULL, (size_t)fs.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    *sz = (size_t)fs.st_size;
    return map;
}
