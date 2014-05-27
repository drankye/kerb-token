/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/otp/otp_state.h - Internal declarations for OTP module */
/*
 * Copyright 2013 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef JWT_H_
#define JWT_H_

#include <k5-int.h>
#include <k5-int-jwt.h>
#include <com_err.h>
#include <jwt_token.h>

/*
 * Client's plugin context
 */
struct _jwt_context {
    int magic;
    char *vendor;
    char *token;
};
typedef struct _jwt_context jwt_context;

/*
 * Client's per-request context
 */
struct _jwt_req_context {
    int magic;
    char *vendor;
    char *token;
};
typedef struct _jwt_req_context jwt_req_context;

/*
 * KDC's (per-realm) plugin context
 */
struct _jwt_kdc_context {
    int magic;
    char *vendor;
};
typedef struct _jwt_kdc_context jwt_kdc_context;

/*
 * KDC's per-request context
 */
struct _jwt_kdc_req_context {
    int magic;
    char *vendor;
    char *token;
};
typedef struct _jwt_kdc_req_context jwt_kdc_req_context;


#endif /* JWT_H_ */
