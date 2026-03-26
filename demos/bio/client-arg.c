/*
 * Copyright 2013-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

/*
 * BIO filter that corrupts outgoing TLS records to trigger
 * "decryption failed or bad record mac" on the server side.
 */
static int docorrupt = 0;

static void copy_flags(BIO *bio)
{
    int flags;
    BIO *next = BIO_next(bio);

    flags = BIO_test_flags(next, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_set_flags(bio, flags);
}

static int tls_corrupt_read(BIO *bio, char *out, int outl)
{
    int ret;
    BIO *next = BIO_next(bio);

    ret = BIO_read(next, out, outl);
    copy_flags(bio);
    return ret;
}

static int tls_corrupt_write(BIO *bio, const char *in, int inl)
{
    int ret;
    BIO *next = BIO_next(bio);
    char *copy;

    if (docorrupt) {
        copy = OPENSSL_memdup(in, inl);
        if (copy == NULL)
            return 0;
        /* Flip last bit of the ciphertext to corrupt MAC/AEAD tag */
        copy[inl - 1] ^= 1;
        ret = BIO_write(next, copy, inl);
        OPENSSL_free(copy);
    } else {
        ret = BIO_write(next, in, inl);
    }
    copy_flags(bio);
    return ret;
}

static long tls_corrupt_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;
    if (cmd == BIO_CTRL_DUP)
        return 0L;
    return BIO_ctrl(next, cmd, num, ptr);
}

static int tls_corrupt_new(BIO *bio)
{
    BIO_set_init(bio, 1);
    return 1;
}

static int tls_corrupt_free(BIO *bio)
{
    BIO_set_init(bio, 0);
    return 1;
}

#define BIO_TYPE_CORRUPT_FILTER (0x80 | BIO_TYPE_FILTER)

static BIO_METHOD *bio_f_corrupt_filter(void)
{
    BIO_METHOD *method = BIO_meth_new(BIO_TYPE_CORRUPT_FILTER,
                                      "TLS corrupt filter");
    if (method == NULL
        || !BIO_meth_set_write(method, tls_corrupt_write)
        || !BIO_meth_set_read(method, tls_corrupt_read)
        || !BIO_meth_set_ctrl(method, tls_corrupt_ctrl)
        || !BIO_meth_set_create(method, tls_corrupt_new)
        || !BIO_meth_set_destroy(method, tls_corrupt_free)) {
        BIO_meth_free(method);
        return NULL;
    }
    return method;
}

int main(int argc, char **argv)
{
    BIO *sbio = NULL, *out = NULL;
    BIO *corrupt_bio = NULL;
    BIO_METHOD *corrupt_method = NULL;
    int len;
    char tmpbuf[1024];
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx;
    SSL *ssl;
    char **args = argv + 1;
    const char *connect_str = "localhost:4433";
    int nargs = argc - 1;
    int ret = EXIT_FAILURE;
    int use_corrupt = 0;

    ctx = SSL_CTX_new(TLS_client_method());
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    while (*args && **args == '-') {
        int rv;
        /* Parse standard arguments */
        rv = SSL_CONF_cmd_argv(cctx, &nargs, &args);
        if (rv == -3) {
            fprintf(stderr, "Missing argument for %s\n", *args);
            goto end;
        }
        if (rv < 0) {
            fprintf(stderr, "Error in command %s\n", *args);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        /* If rv > 0 we processed something so proceed to next arg */
        if (rv > 0)
            continue;
        /* Otherwise application specific argument processing */
        if (strcmp(*args, "-connect") == 0) {
            connect_str = args[1];
            if (connect_str == NULL) {
                fprintf(stderr, "Missing -connect argument\n");
                goto end;
            }
            args += 2;
            nargs -= 2;
            continue;
        } else if (strcmp(*args, "-corrupt") == 0) {
            use_corrupt = 1;
            args++;
            nargs--;
            continue;
        } else {
            fprintf(stderr, "Unknown argument %s\n", *args);
            goto end;
        }
    }

    if (!SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Finish error\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /*
     * We'd normally set some stuff like the verify paths and * mode here
     * because as things stand this will connect to * any server whose
     * certificate is signed by any CA.
     */

    sbio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(sbio, &ssl);

    if (!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        goto end;
    }

    /* We might want to do other things with ssl here */

    BIO_set_conn_hostname(sbio, connect_str);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* Print the local (client) port */
    {
        int fd;
        struct sockaddr_storage sa;
        socklen_t sa_len = sizeof(sa);

        BIO_get_fd(SSL_get_rbio(ssl), &fd);
        if (fd >= 0 && getsockname(fd, (struct sockaddr *)&sa, &sa_len) == 0) {
            if (sa.ss_family == AF_INET)
                fprintf(stderr, "Client port: %d\n",
                        ntohs(((struct sockaddr_in *)&sa)->sin_port));
            else if (sa.ss_family == AF_INET6)
                fprintf(stderr, "Client port: %d\n",
                        ntohs(((struct sockaddr_in6 *)&sa)->sin6_port));
        }
    }

    if (use_corrupt) {
        /*
         * Insert a corruption filter between SSL and the socket.
         * The handshake is already done, so only application data
         * will be corrupted.
         */
        BIO *underlying;

        corrupt_method = bio_f_corrupt_filter();
        if (corrupt_method == NULL) {
            fprintf(stderr, "Failed to create corrupt BIO method\n");
            goto end;
        }
        corrupt_bio = BIO_new(corrupt_method);
        if (corrupt_bio == NULL) {
            fprintf(stderr, "Failed to create corrupt BIO\n");
            goto end;
        }

        /*
         * Rewire: take the socket BIO out from under the SSL BIO
         * and push the corrupt filter in between.
         */
        underlying = SSL_get_rbio(ssl);
        BIO_up_ref(underlying);
        BIO_push(corrupt_bio, underlying);
        SSL_set_bio(ssl, corrupt_bio, corrupt_bio);

        docorrupt = 1;
        fprintf(stderr, "*** Corruption enabled: outgoing records will be corrupted ***\n");
    }

    /* Could examine ssl here to get connection info */

    BIO_puts(sbio, "GET /robots.txt HTTP/1.0\n\n");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);
    }
    if (use_corrupt) {
        fprintf(stderr, "*** Server should have seen: ***\n");
        fprintf(stderr, "  error:0A000119:SSL routines::decryption failed or bad record mac\n");
        fprintf(stderr, "  error:0A000139:SSL routines::record layer failure\n");
    }
    ret = EXIT_SUCCESS;
end:
    SSL_CONF_CTX_free(cctx);
    if (!use_corrupt)
        BIO_free_all(sbio);
    else
        BIO_free_all(sbio); /* corrupt_bio is freed as part of ssl's chain */
    BIO_free(out);
    BIO_meth_free(corrupt_method);
    return ret;
}
