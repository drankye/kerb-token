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

int show_flags = 0, show_time = 0, status_only = 0, show_keys = 0;
int show_etype = 0, show_addresses = 0, no_resolve = 0, print_version = 0;
int show_adtype = 0, show_all = 0, list_all = 0, use_client_keytab = 0;
int show_config = 0;
char *defname;
char *progname;
krb5_int32 now;
unsigned int timestamp_width;

krb5_context kcontext;

char * etype_string (krb5_enctype );
void show_credential (krb5_creds *);

void list_all_ccaches (void);
int list_ccache (krb5_ccache);
void show_all_ccaches (void);
void do_ccache_name (char *);
int do_ccache (krb5_ccache);
void do_keytab (char *);
void printtime (time_t);
void one_addr (krb5_address *);
void fillit (FILE *, unsigned int, int);

#define DEFAULT 0
#define CCACHE 1
#define KEYTAB 2

static void usage()
{
#define KRB_AVAIL_STRING(x) ((x)?"available":"not available")

    fprintf(stderr, _("Usage: %s [-e] [-V] [[-c] [-l] [-A] [-d] [-f] [-s] "
                      "[-a [-n]]] [-k [-t] [-K]] [name]\n"), progname);
    fprintf(stderr, _("\t-c specifies credentials cache\n"));
    fprintf(stderr, _("\t-k specifies keytab\n"));
    fprintf(stderr, _("\t   (Default is credentials cache)\n"));
    fprintf(stderr, _("\t-i uses default client keytab if no name given\n"));
    fprintf(stderr, _("\t-l lists credential caches in collection\n"));
    fprintf(stderr, _("\t-A shows content of all credential caches\n"));
    fprintf(stderr, _("\t-e shows the encryption type\n"));
    fprintf(stderr, _("\t-V shows the Kerberos version and exits\n"));
    fprintf(stderr, _("\toptions for credential caches:\n"));
    fprintf(stderr, _("\t\t-d shows the submitted authorization data "
                      "types\n"));
    fprintf(stderr, _("\t\t-f shows credentials flags\n"));
    fprintf(stderr, _("\t\t-s sets exit status based on valid tgt "
                      "existence\n"));
    fprintf(stderr, _("\t\t-a displays the address list\n"));
    fprintf(stderr, _("\t\t\t-n do not reverse-resolve\n"));
    fprintf(stderr, _("\toptions for keytabs:\n"));
    fprintf(stderr, _("\t\t-t shows keytab entry timestamps\n"));
    fprintf(stderr, _("\t\t-K shows keytab entry keys\n"));
    exit(1);
}


int
main(argc, argv)
    int argc;
    char **argv;
{
    char *token = NULL;
    jwt_token out_token;

    if (argc > 1) {
        token = argv[1];
    }

    jwt_token_decode(token, &out_token);



    return 0;
}