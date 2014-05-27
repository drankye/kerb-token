/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* clients/tlist/tlist.c - List contents of credential cache or keytab */
/*
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include <krb5.h>
#include <com_err.h>
#include <locale.h>
#include <stdlib.h>
#include <jwt_token.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _WIN32
#include <getopt.h>
#endif
#include <string.h>
#include <stdio.h>
#include <time.h>
/* Need definition of INET6 before network headers, for IRIX.  */
#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/')+1 : (x))
#else
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#endif

extern int optind;
char *progname;

static void usage()
{
    fprintf(stderr, _("Usage: %s [token]\n"), progname);

    exit(1);
}


int
main(argc, argv)
    int argc;
    char **argv;
{
    char *token = NULL;
    jwt_token *out_token;

    setlocale(LC_ALL, "");
    progname = GET_PROGNAME(argv[0]);

    if (argc > 1) {
        token = argv[1];
    } else {
        usage();
    }

    jwt_token_decode(token, &out_token);

    return 0;
}