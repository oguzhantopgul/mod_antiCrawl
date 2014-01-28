/*
mod_anticrawl for Apache 2
@author Oguzhan Topgul 
@mail oguzhantopgul@gmail.com

mod_anticralw is an Apache module that fights against web site crawlers, bots, and automated vulnerability scanners
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>


#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_strmatch.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_want.h"
#include "apr_global_mutex.h"


module AP_MODULE_DECLARE_DATA anticrawl_module;

/* BEGIN Anticrawler Definitions */

#define MAILER	"/bin/mail %s"
#define  LOG( A, ... ) { openlog("mod_anticrawl", LOG_PID, LOG_DAEMON); syslog( A, __VA_ARGS__ ); closelog(); }

#define DEFAULT_HASH_TBL_SIZE   3097ul      // Default hash table size
#define DEFAULT_COUNT      100                // Default maximum site hit count per interval
#define DEFAULT_INTERVAL   3               // Default 1 Second site interval
#define DEFAULT_BLOCKING_PERIOD 3600          // Default for Detected IPs; blocked for 10 seconds
#define DEFAULT_LOG_DIR		"/tmp"      // Default temp directory

/* END Anticrawler Definitions */

/* BEGIN tree (Named Timestamp Tree) Headers */

enum {
    tree_num_primes = 28
};

apr_global_mutex_t *mutex;

/* tree root tree */
struct tree {
    long size;
    long items;
    struct tree_node **tbl;
};

/* tree node (entry in the tree root tree) */
struct tree_node {
    char *key;
    time_t timestamp;
    long count;
    struct tree_node *next;
};

/* tree cursor */
struct tree_c {
    long iter_index;
    struct tree_node *iter_next;
};


struct tree *tree_create(long size);
int tree_destroy(struct tree *tree);
struct tree_node *tree_find(struct tree *tree, const char *key);
struct tree_node *tree_insert(struct tree *tree, const char *key);
int tree_delete(struct tree *tree, const char *key);
long tree_hashcode(struct tree *tree, const char *key);
struct tree_node *c_tree_first(struct tree *tree, struct tree_c *c);
struct tree_node *c_tree_next(struct tree *tree, struct tree_c *c);
void mymutex_lock();
void mymutex_unlock();
/* END tree (Named Timestamp Tree) Headers */


/* Inject Function Related Structs */
static const char injection_filter_name[] = "INJECT";

typedef struct inject_pattern_t {
    const apr_strmatch_pattern *pattern;
    const ap_regex_t *regexp;
    const char *replacement;
    apr_size_t replen;
    apr_size_t patlen;
    int flatten;
} inject_pattern_t;

typedef struct {
    apr_array_header_t *patterns;
} inject_dir_conf;

typedef struct {
    apr_bucket_brigade *linebb;
    apr_bucket_brigade *linesbb;
    apr_bucket_brigade *passbb;
    apr_bucket_brigade *pattbb;
    apr_pool_t *tpool;
} injection_module_ctx;

#define AP_MAX_BUCKETS 1000

#define SEDSCAT(s1, s2, pool, buff, blen, repl) do { \
    if (!s1) {                                       \
        s1 = apr_pstrmemdup(pool, buff, blen);       \
    }                                                \
    else {                                           \
        s2 = apr_pstrmemdup(pool, buff, blen);       \
        s1 = apr_pstrcat(pool, s1, s2, NULL);        \
    }                                                \
    s1 = apr_pstrcat(pool, s1, repl, NULL);          \
} while (0)

#define SEDRMPATBCKT(b, offset, tmp_b, patlen) do {  \
    apr_bucket_split(b, offset);                     \
    tmp_b = APR_BUCKET_NEXT(b);                      \
    apr_bucket_split(tmp_b, patlen);                 \
    b = APR_BUCKET_NEXT(tmp_b);                      \
    apr_bucket_delete(tmp_b);                        \
} while (0)

/* END Inject Related Structs Globals*/

/* BEGIN Anticrawler Globals */

struct tree *timetable; // Our dynamic hash table

static unsigned long hash_table_size = DEFAULT_HASH_TBL_SIZE;
static int interval = DEFAULT_INTERVAL;
static int count = DEFAULT_COUNT;
static int blocking_period = DEFAULT_BLOCKING_PERIOD;
static char *email_notify = NULL;
static char *log_dir = NULL;
static char *system_command = NULL;

/* END Anticrawler Globals */

static void * create_timetable(apr_pool_t *p, server_rec *s) {
    /* Create a new hit list (timetable) for this listener */

    timetable = tree_create(hash_table_size);
}

/* Inject operation Configs */

static void *create_injection_dcfg(apr_pool_t *p, char *d) {
    inject_dir_conf *dcfg =
            (inject_dir_conf *) apr_pcalloc(p, sizeof (inject_dir_conf));

    dcfg->patterns = apr_array_make(p, 10, sizeof (inject_pattern_t));
    return dcfg;
}

static void *merge_injection_dcfg(apr_pool_t *p, void *basev, void *overv) {
    inject_dir_conf *a =
            (inject_dir_conf *) apr_pcalloc(p, sizeof (inject_dir_conf));
    inject_dir_conf *base = (inject_dir_conf *) basev;
    inject_dir_conf *over = (inject_dir_conf *) overv;

    a->patterns = apr_array_append(p, over->patterns,
            base->patterns);
    return a;
}

/* End of Inject operation Configs */

static void do_pattmatch(ap_filter_t *f, apr_bucket *inb,
        apr_bucket_brigade *mybb,
        apr_pool_t *tmp_pool) {
    int i;
    int force_quick = 0;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    apr_size_t bytes;
    apr_size_t len;
    apr_size_t fbytes;
    const char *buff;
    const char *repl;
    char *scratch;
    char *p;
    char *s1;
    char *s2;
    apr_bucket *b;
    apr_bucket *tmp_b;
    apr_pool_t *tpool;

    inject_dir_conf *cfg =
            (inject_dir_conf *) ap_get_module_config(f->r->per_dir_config,
            &anticrawl_module);
    inject_pattern_t *script;

    APR_BRIGADE_INSERT_TAIL(mybb, inb);

    script = (inject_pattern_t *) cfg->patterns->elts;
    apr_pool_create(&tpool, tmp_pool);
    scratch = NULL;
    fbytes = 0;

    if (cfg->patterns->nelts == 1) {
        force_quick = 1;
    }
    for (i = 0; i < cfg->patterns->nelts; i++) {
        for (b = APR_BRIGADE_FIRST(mybb);
                b != APR_BRIGADE_SENTINEL(mybb);
                b = APR_BUCKET_NEXT(b)) {
            if (APR_BUCKET_IS_METADATA(b)) {

                continue;
            }
            if (apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ)
                    == APR_SUCCESS) {
                s1 = NULL;
                if (script->pattern) {
                    while ((repl = apr_strmatch(script->pattern, buff, bytes))) {
                        /* get offset into buff for pattern */
                        len = (apr_size_t) (repl - buff);
                        if (script->flatten && !force_quick) {

                            SEDSCAT(s1, s2, tmp_pool, buff, len,
                                    script->replacement);
                        } else {

                            SEDRMPATBCKT(b, len, tmp_b, script->patlen);

                            tmp_b = apr_bucket_transient_create(script->replacement,
                                    script->replen,
                                    f->r->connection->bucket_alloc);

                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        }

                        len += script->patlen;
                        bytes -= len;
                        buff += len;
                    }
                    if (script->flatten && s1 && !force_quick) {

                        s2 = apr_pstrmemdup(tmp_pool, buff, bytes);
                        s1 = apr_pstrcat(tmp_pool, s1, s2, NULL);
                        tmp_b = apr_bucket_transient_create(s1, strlen(s1),
                                f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        apr_bucket_delete(b);
                        b = tmp_b;
                    }

                } else if (script->regexp) {

                    if (!scratch || (bytes > (fbytes + 1))) {
                        fbytes = bytes + 1;
                        scratch = apr_palloc(tpool, fbytes);
                    }
                    /* reset pointer to the scratch space */
                    p = scratch;
                    memcpy(p, buff, bytes);
                    p[bytes] = '\0';
                    while (!ap_regexec(script->regexp, p,
                            AP_MAX_REG_MATCH, regm, 0)) {
                        /* first, grab the replacement string */
                        repl = ap_pregsub(tmp_pool, script->replacement, p,
                                AP_MAX_REG_MATCH, regm);
                        if (script->flatten && !force_quick) {
                            SEDSCAT(s1, s2, tmp_pool, p, regm[0].rm_so, repl);
                        } else {
                            len = (apr_size_t) (regm[0].rm_eo - regm[0].rm_so);
                            SEDRMPATBCKT(b, regm[0].rm_so, tmp_b, len);
                            tmp_b = apr_bucket_transient_create(repl,
                                    strlen(repl),
                                    f->r->connection->bucket_alloc);
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        }

                        p += regm[0].rm_eo;
                    }
                    if (script->flatten && s1 && !force_quick) {
                        s1 = apr_pstrcat(tmp_pool, s1, p, NULL);
                        tmp_b = apr_bucket_transient_create(s1, strlen(s1),
                                f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        apr_bucket_delete(b);
                        b = tmp_b;
                    }

                } else {
                    continue;
                }
            }
        }
        script++;
    }

    apr_pool_destroy(tpool);

    return;
}

static int access_checker(request_rec *r) {
    int ret = OK;

    /* BEGIN Anticrawler Code */
    mymutex_lock();

    if (r->prev == NULL && r->main == NULL && timetable != NULL) {
        char hash_key[2048];
        struct tree_node *n;
        time_t t = time(NULL);

        /* First see if the IP itself is on Blacklist */
        snprintf(hash_key, 2048, "%s_BLOCKED", r->connection->remote_ip);
        n = tree_find(timetable, hash_key);
        if (n != NULL) {
            if (t - n->timestamp < blocking_period) {
                ap_log_error("xx", 1, 1, 0, NULL, "IP found on blacklist: %s, counter= %ld", n->key, n->count);
                /* If the IP is on "hold", make it wait longer in 403 land */
                ret = HTTP_NOT_FOUND;
                n->timestamp = time(NULL);
            } else {
                // if blocking period is over delete from Blacklist and insert into Hitlist
                snprintf(hash_key, 2048, "%s_BLOCKED", r->connection->remote_ip);
                tree_delete(timetable, hash_key);
                tree_insert(timetable, r->connection->remote_ip);
            }
            /* Not on Blacklist, check hit stats */
        } else {
            /* IF Crawler Hits the Trap */
            int dclen=strlen("/dontclick.html");
            int rurilen=strlen(r->uri);        
            if (rurilen >= dclen)
            if (strcmp(r->uri + rurilen - dclen , "/dontclick.html") == 0) {
                ret = HTTP_NOT_FOUND;
                ap_log_error("xx", 1, 1, 0, NULL, "IP hit the trap");
                snprintf(hash_key, 2048, "%s_BLOCKED", r->connection->remote_ip);
                tree_insert(timetable, hash_key);
                n = tree_find(timetable, r->connection->remote_ip);
                if (n != NULL) {
                    tree_delete(timetable, r->connection->remote_ip);
                }

            } else {

                /* Has IP  hit too much? */

                n = tree_find(timetable, r->connection->remote_ip);
                if (n != NULL) {
                    ap_log_error("xx", 1, 1, 0, NULL, "IP found on hitlist: %s, counter= %ld", n->key, n->count);
                    /* If IP is being hit too much, add to "hold" list and 403 */
                    if (t - n->timestamp < interval && n->count >= count) {
                        ap_log_error("xx", 1, 1, 0, NULL, "IP %s hits too much, counter= %ld", n->key, n->count);
                        ret = HTTP_NOT_FOUND;
                        snprintf(hash_key, 2048, "%s_BLOCKED", r->connection->remote_ip);
                        tree_insert(timetable, hash_key);
                        tree_delete(timetable, r->connection->remote_ip);
                    } else {

                        /* Reset our hit count list as necessary */
                        if (t - n->timestamp >= interval) {
                            n->count = 0;
                            ap_log_error("xx", 1, 1, 0, NULL, "IP found on hitlist: %s, but we set counter to = %ld", n->key, n->count);
                            n->timestamp = t; //DEBUG: Bunu ekledim
                        }
                    }
                    //n->timestamp = t; //Bunu kaldırıp üsttekini ekle
                    n->count++;
                } else {
                    //ap_log_error("xx", 1, 1, 0, NULL,"IP could not be found on hitlist: %s, counter= %ld",n->key,n->count);
                    tree_insert(timetable, r->connection->remote_ip);
                }

            }
        }

    } /* if (r->prev == NULL && r->main == NULL && timetable != NULL) */

    /* END Anticrawler Code */
    /*
    if (ret == HTTP_NOT_ACCEPTABLE && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "client denied by server configuration: %s",
                r->filename);
    }*/
    mymutex_unlock();

    return ret;
}

static apr_status_t injection_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    apr_size_t bytes;
    apr_size_t len;
    apr_size_t fbytes;
    const char *buff;
    const char *nl = NULL;
    char *bflat;
    apr_bucket *b;
    apr_bucket *tmp_b;
    apr_bucket_brigade *tmp_bb = NULL;
    apr_status_t rv;

    injection_module_ctx *ctx = f->ctx;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof (*ctx));

        ctx->linebb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->linesbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->pattbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

        ctx->passbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        /* Create our temporary pool only once */
        apr_pool_create(&(ctx->tpool), f->r->pool);
        apr_table_unset(f->r->headers_out, "Content-Length");
    }
    /*
     * Shortcircuit
     */
    if (APR_BRIGADE_EMPTY(bb))
        return APR_SUCCESS;

    while ((b = APR_BRIGADE_FIRST(bb)) && (b != APR_BRIGADE_SENTINEL(bb))) {
        if (APR_BUCKET_IS_EOS(b)) {

            if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                        &fbytes, ctx->tpool);
                tmp_b = apr_bucket_transient_create(bflat, fbytes,
                        f->r->connection->bucket_alloc);
                do_pattmatch(f, tmp_b, ctx->pattbb, ctx->tpool);
                APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
            }
            apr_brigade_cleanup(ctx->linebb);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        } else if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        } else {
            rv = apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ);
            if (rv != APR_SUCCESS || bytes == 0) {
                apr_bucket_delete(b);
            } else {
                int num = 0;
                while (bytes > 0) {
                    nl = memchr(buff, APR_ASCII_LF, bytes);
                    if (nl) {
                        len = (apr_size_t) (nl - buff) + 1;
                        /* split *after* the newline */
                        apr_bucket_split(b, len);

                        bytes -= len;
                        buff += len;

                        tmp_b = APR_BUCKET_NEXT(b);
                        APR_BUCKET_REMOVE(b);

                        if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                            APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                            rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                    &fbytes, ctx->tpool);
                            b = apr_bucket_transient_create(bflat, fbytes,
                                    f->r->connection->bucket_alloc);
                            apr_brigade_cleanup(ctx->linebb);
                        }
                        do_pattmatch(f, b, ctx->pattbb, ctx->tpool);

                        for (b = APR_BRIGADE_FIRST(ctx->pattbb);
                                b != APR_BRIGADE_SENTINEL(ctx->pattbb);
                                b = APR_BUCKET_NEXT(b)) {
                            num++;
                        }
                        APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);

                        // for safety reasons flush bb
                        if (num > AP_MAX_BUCKETS) {
                            b = apr_bucket_flush_create(
                                    f->r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
                            rv = ap_pass_brigade(f->next, ctx->passbb);
                            apr_brigade_cleanup(ctx->passbb);
                            num = 0;
                            apr_pool_clear(ctx->tpool);
                            if (rv != APR_SUCCESS)
                                return rv;
                        }
                        b = tmp_b;
                    } else {
                        //no newline
                        APR_BUCKET_REMOVE(b);
                        APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                        bytes = 0;
                    }
                }
            }
        }
        if (!APR_BRIGADE_EMPTY(ctx->passbb)) {
            rv = ap_pass_brigade(f->next, ctx->passbb);
            apr_brigade_cleanup(ctx->passbb);
            if (rv != APR_SUCCESS) {
                apr_pool_clear(ctx->tpool);
                return rv;
            }
        }
        apr_pool_clear(ctx->tpool);
    }

    /* Anything left we want to save/setaside for the next go-around */
    if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
        /*
         * Provide ap_save_brigade with an existing empty brigade
         * (ctx->linesbb) to avoid creating a new one.
         */
        ap_save_brigade(f, &(ctx->linesbb), &(ctx->linebb), f->r->pool);
        tmp_bb = ctx->linebb;
        ctx->linebb = ctx->linesbb;
        ctx->linesbb = tmp_bb;
    }

    return APR_SUCCESS;
}

static apr_status_t destroy_timetable(void *not_used) {
    tree_destroy(timetable);
    free(email_notify);
    free(system_command);
}


/* BEGIN tree (Named Timestamp Tree) Functions */

static unsigned long tree_prime_list[tree_num_primes] = {
    53ul, 97ul, 193ul, 389ul, 769ul,
    1543ul, 3079ul, 6151ul, 12289ul, 24593ul,
    49157ul, 98317ul, 196613ul, 393241ul, 786433ul,
    1572869ul, 3145739ul, 6291469ul, 12582917ul, 25165843ul,
    50331653ul, 100663319ul, 201326611ul, 402653189ul, 805306457ul,
    1610612741ul, 3221225473ul, 4294967291ul
};

/* Find the numeric position in the hash table based on key and modulus */

long tree_hashcode(struct tree *tree, const char *key) {
    unsigned long val = 0;
    for (; *key; ++key) val = 5 * val + *key;
    return (val % tree->size);
}

/* Creates a single node in the tree */

struct tree_node *tree_node_create(const char *key) {
    char *node_key;
    struct tree_node* node;

    node = (struct tree_node *) malloc(sizeof (struct tree_node));
    if (node == NULL) {
        return NULL;
    }
    if ((node_key = strdup(key)) == NULL) {
        free(node);
        return NULL;
    }
    node->key = node_key;
    node->timestamp = time(NULL);
    node->next = NULL;
    return (node);
}

/* Tree initializer */

struct tree *tree_create(long size) {
    long i = 0;
    struct tree *tree;

    tree = (struct tree *) malloc(sizeof (struct tree));

    if (tree == NULL)
        return NULL;
    while (tree_prime_list[i] < size) {
        i++;
    }
    tree->size = tree_prime_list[i];
    tree->items = 0;
    tree->tbl = (struct tree_node **) calloc(tree->size, sizeof (struct tree_node *));
    if (tree->tbl == NULL) {
        free(tree);
        return NULL;
    }
    return (tree);
}

/* Find an object in the tree */

struct tree_node *tree_find(struct tree *tree, const char *key) {
    long hash_code;
    struct tree_node *node;

    if (tree == NULL) return NULL;

    hash_code = tree_hashcode(tree, key);
    node = tree->tbl[hash_code];

    while (node) {
        if (!strcmp(key, node->key)) {
            return (node);
        }
        node = node->next;
    }
    return ((struct tree_node *) NULL);
}

void write_to_file() {
    long i;
    FILE *f = fopen("/dev/shm/anticrawl-data", "w");
    for (i = 0; i < timetable->size; i++) {
        if (timetable->tbl[i] != NULL) {
            fprintf(f, "%s\n", timetable->tbl[i]->key);
            fprintf(f, "%ld\n", timetable->tbl[i]->count);
            fprintf(f, "%ld\n", timetable->tbl[i]->timestamp);
        }
    }
    fprintf(f, "EOF\n");
    fclose(f);
}

void read_from_file() {
    char *key = malloc(80 * sizeof (char));
    long count;
    time_t timestamp;
    FILE *f = fopen("/dev/shm/anticrawl-data", "r");
    if (f == NULL)
        return;
    int finished = 0;
    timetable->tbl = (struct tree_node **) calloc(timetable->size, sizeof (struct tree_node *));
    while (!finished) {
        fscanf(f, "%s", key);
        if (strcmp("EOF", key) == 0) {
            finished = 1;
        } else {
            fscanf(f, "%ld", &count);
            fscanf(f, "%ld", &timestamp);
            tree_insert(timetable, key);
            struct tree_node *t = tree_find(timetable, key);
            t->count = count;
            t->timestamp = timestamp;
        }
    }
    fclose(f);
}

void mymutex_lock() {
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, 0, "mutex lock start");
    int rv = apr_global_mutex_lock(mutex);
    if (rv != APR_SUCCESS) {
        char *buf = malloc(sizeof (char) *200);
        char* r = apr_strerror(rv,
                buf,
                200
                );
        ap_log_error("xx", 1, 1, 0, NULL, "apr_global_mutex_lock failed %s", r);

    } else
        read_from_file();

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, 0, "mutex lock end");

}

void mymutex_unlock() {
    write_to_file();
    int rv = apr_global_mutex_unlock(mutex);
    if (rv != APR_SUCCESS) {
        ap_log_error("xx", 1, 1, 0, NULL, "apr_global_mutex_lock failed");
    }
}

/* Insert a node into the tree */

struct tree_node *tree_insert(struct tree *tree, const char *key) {
    long hash_code;
    struct tree_node *parent;
    struct tree_node *node;
    struct tree_node *new_node = NULL;
    struct tree_node *result = NULL;
    time_t timestamp = time(NULL);

    if (tree == NULL)
        result = NULL;
    else {
        hash_code = tree_hashcode(tree, key);
        parent = NULL;
        node = tree->tbl[hash_code];

        while (node != NULL) {
            if (strcmp(key, node->key) == 0) {
                new_node = node;
                node = NULL;
            }

            if (new_node == NULL) {
                parent = node;
                node = node->next;
            }
        }

        if (new_node != NULL) {
            new_node->timestamp = timestamp;
            new_node->count = 1;
            result = new_node;
        } else {

            /* Create a new node */
            new_node = tree_node_create(key);
            new_node->timestamp = timestamp;
            //new_node->timestamp = 0;
            new_node->count = 1; //DEBUG: Bunu ekledim ust satiri comment ettim
            tree->items++;

            /* Insert */
            if (parent) { /* Existing parent */
                parent->next = new_node;
                result = new_node; /* Return the locked node */
            } else {

                /* No existing parent; add directly to hash table */
                tree->tbl[hash_code] = new_node;
                result = new_node;
            }
        }
    }
    return result;
}

/* Tree destructor */

int tree_destroy(struct tree *tree) {
    struct tree_node *node, *next;
    struct tree_c c;
    int result;

    mymutex_lock();

    if (tree == NULL) {
        result = -1;
    } else {
        node = c_tree_first(tree, &c);
        while (node != NULL) {
            next = c_tree_next(tree, &c);
            tree_delete(tree, node->key);
            node = next;
        }

        free(tree->tbl);
        free(tree);
        tree = (struct tree *) NULL;

        result = 0;
    }
    mymutex_unlock();
    return result;
}

/* Delete a single node in the tree */

int tree_delete(struct tree *tree, const char *key) {
    long hash_code;
    struct tree_node *parent = NULL;
    struct tree_node *node;
    struct tree_node *del_node = NULL;
    int result;

    if (tree == NULL) {
        result = -1;
    } else {
        hash_code = tree_hashcode(tree, key);
        node = tree->tbl[hash_code];

        while (node != NULL) {
            if (strcmp(key, node->key) == 0) {
                del_node = node;
                node = NULL;
            }

            if (del_node == NULL) {
                parent = node;
                node = node->next;
            }
        }

        if (del_node != NULL) {

            if (parent) {
                parent->next = del_node->next;
            } else {
                tree->tbl[hash_code] = del_node->next;
            }

            free(del_node->key);
            free(del_node);
            tree->items--;

            result = 0;
        } else


            result = -5;
    }
    return result;
}

/* Point cursor to first item in tree */

struct tree_node *c_tree_first(struct tree *tree, struct tree_c *c) {

    c->iter_index = 0;
    c->iter_next = (struct tree_node *) NULL;
    return (c_tree_next(tree, c));
}

/* Point cursor to next iteration in tree */

struct tree_node *c_tree_next(struct tree *tree, struct tree_c *c) {
    long index;
    struct tree_node *node = c->iter_next;

    if (tree == NULL) return NULL;

    if (node) {
        if (node != NULL) {
            c->iter_next = node->next;
            return (node);
        }
    }

    if (!node) {
        while (c->iter_index < tree->size) {
            index = c->iter_index++;

            if (tree->tbl[index]) {
                c->iter_next = tree->tbl[index]->next;
                return (tree->tbl[index]);
            }
        }
    }
    return ((struct tree_node *) NULL);
}

/* END tree (Named Pointer Tree) Functions */

/* BEGIN Configuration Functions */

static const char *
get_hash_tbl_size(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);

    if (n <= 0) {
        hash_table_size = DEFAULT_HASH_TBL_SIZE;
    } else {
        hash_table_size = n;
    }

    return NULL;
}

static const char *
get_count(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        count = DEFAULT_COUNT;
    } else {
        count = n;
    }

    return NULL;
}

static const char *
get_interval(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        interval = DEFAULT_INTERVAL;
    } else {
        interval = n;
    }

    return NULL;
}

static const char *
get_blocking_period(cmd_parms *cmd, void *dconfig, const char *value) {
    long n = strtol(value, NULL, 0);
    if (n <= 0) {
        blocking_period = DEFAULT_BLOCKING_PERIOD;
    } else {
        blocking_period = n;
    }

    return NULL;
}

static const char *
get_log_dir(cmd_parms *cmd, void *dconfig, const char *value) {
    if (value != NULL && value[0] != 0) {
        if (log_dir != NULL)
            free(log_dir);
        log_dir = strdup(value);
    }

    return NULL;
}

static const char *
get_email_notify(cmd_parms *cmd, void *dconfig, const char *value) {
    if (value != NULL && value[0] != 0) {
        if (email_notify != NULL)
            free(email_notify);
        email_notify = strdup(value);
    }

    return NULL;
}

static const char *
get_system_command(cmd_parms *cmd, void *dconfig, const char *value) {
    if (value != NULL && value[0] != 0) {
        if (system_command != NULL)
            free(system_command);
        system_command = strdup(value);
    }

    return NULL;
}

static const char *
set_pattern(cmd_parms *cmd, void *cfg, const char *line) {
    char *from = NULL;
    char *to = NULL;
    char *flags = NULL;
    char *ourline;
    char delim;
    inject_pattern_t *nscript;
    int is_pattern = 0;
    int ignore_case = 0;
    int flatten = 1;
    ap_regex_t *r = NULL;

    if (apr_tolower(*line) != 's') {
        return "Bad Substitute format, must be an s/// pattern";
    }
    ourline = apr_pstrdup(cmd->pool, line);
    delim = *++ourline;
    if (delim)
        from = ++ourline;
    if (from) {
        if (*ourline != delim) {
            while (*++ourline && *ourline != delim);
        }
        if (*ourline) {
            *ourline = '\0';
            to = ++ourline;
        }
    }
    if (to) {
        if (*ourline != delim) {
            while (*++ourline && *ourline != delim);
        }
        if (*ourline) {
            *ourline = '\0';
            flags = ++ourline;
        }
    }

    if (!delim || !from || !*from || !to) {
        return "Bad Substitute format, must be a complete s/// pattern";
    }

    if (flags) {
        while (*flags) {
            delim = apr_tolower(*flags); /* re-use */
            if (delim == 'i')
                ignore_case = 1;
            else if (delim == 'n')
                is_pattern = 1;
            else if (delim == 'f')
                flatten = 1;
            else if (delim == 'q')
                flatten = 0;
            else
                return "Bad Substitute flag, only s///[infq] are supported";
            flags++;
        }
    }

    /* first see if we can compile the regex */
    if (!is_pattern) {
        r = ap_pregcomp(cmd->pool, from, AP_REG_EXTENDED |
                (ignore_case ? AP_REG_ICASE : 0));
        if (!r)
            return "Substitute could not compile regex";
    }
    nscript = apr_array_push(((inject_dir_conf *) cfg)->patterns);
    /* init the new entries */
    nscript->pattern = NULL;
    nscript->regexp = NULL;
    nscript->replacement = NULL;
    nscript->patlen = 0;

    if (is_pattern) {
        nscript->patlen = strlen(from);
        nscript->pattern = apr_strmatch_precompile(cmd->pool, from,
                !ignore_case);
    } else {
        nscript->regexp = r;
    }

    nscript->replacement = to;
    nscript->replen = strlen(to);
    nscript->flatten = flatten;

    return NULL;
}

/* END Configuration Functions */

static const command_rec access_cmds[] = {
    AP_INIT_TAKE1("HashTableSize", get_hash_tbl_size, NULL, RSRC_CONF,
    "Set size of hash table"),

    AP_INIT_TAKE1("Count", get_count, NULL, RSRC_CONF,
    "Set maximum hit count per interval"),

    AP_INIT_TAKE1("Interval", get_interval, NULL, RSRC_CONF,
    "Set interval"),

    AP_INIT_TAKE1("BlockingPeriod", get_blocking_period, NULL, RSRC_CONF,
    "Set blocking period for detected crawler IPs"),

    AP_INIT_TAKE1("EmailNotify", get_email_notify, NULL, RSRC_CONF,
    "Set email notification"),

    AP_INIT_TAKE1("LogDir", get_log_dir, NULL, RSRC_CONF,
    "Set log dir"),

    AP_INIT_TAKE1("SystemCommand", get_system_command, NULL, RSRC_CONF,
    "Set system command on crawler"),

    AP_INIT_TAKE1("Inject", set_pattern, NULL, OR_ALL,
    "Pattern to filter the response content (s/foo/bar/[inf])"), {
        NULL
    }
};

static int shm_tree_post_config(apr_pool_t *pconf, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s) {
    int rv;

    rv = apr_global_mutex_create(&(mutex), "anticrawl-lock",
            APR_LOCK_DEFAULT, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "Failed to create mutex");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    int status = unixd_set_global_mutex_perms(mutex);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "Failed to set mutex perms");
        return status;
    }

    return OK;

}

static void shm_tree_child_init(apr_pool_t *p, server_rec *s) {


    int rv = apr_global_mutex_child_init(&mutex,
            "anticrawl-lock", p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "Failed to attach to mutex");
        return;
    }
}

static void register_hooks(apr_pool_t *p) {
    ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter(injection_filter_name, injection_filter,
            NULL, AP_FTYPE_RESOURCE);
    apr_pool_cleanup_register(p, NULL, apr_pool_cleanup_null, destroy_timetable);
    ap_hook_post_config(shm_tree_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_child_init(shm_tree_child_init, NULL, NULL,
            APR_HOOK_REALLY_FIRST);
};

module AP_MODULE_DECLARE_DATA anticrawl_module = {
    STANDARD20_MODULE_STUFF,
    create_injection_dcfg, /* dir config creater */
    merge_injection_dcfg, /* dir merger --- default is to override */
    create_timetable,
    NULL,
    access_cmds,
    register_hooks
};

