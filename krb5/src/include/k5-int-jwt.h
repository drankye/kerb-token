/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/jwt.h - jwt routines */
/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef JWT_H
#define JWT_H

#include <k5-json.h>

typedef struct _krb5_jwt_tokeninfo {
    krb5_data vendor;
} krb5_jwt_tokeninfo;

typedef struct _krb5_pa_jwt_challenge {
    krb5_jwt_tokeninfo **tokeninfo;
} krb5_pa_jwt_challenge;

typedef struct _krb5_pa_jwt_req {
	krb5_data vendor;
    krb5_data token;
} krb5_pa_jwt_req;

void k5_free_jwt_tokeninfo(krb5_context context, krb5_jwt_tokeninfo *val);
void k5_free_pa_jwt_challenge(krb5_context context,
                              krb5_pa_jwt_challenge *val);
void k5_free_pa_jwt_req(krb5_context context, krb5_pa_jwt_req *val);

krb5_error_code
encode_krb5_jwt_tokeninfo(const krb5_jwt_tokeninfo *, krb5_data **);

krb5_error_code
encode_krb5_pa_jwt_challenge(const krb5_pa_jwt_challenge *, krb5_data **);

krb5_error_code
encode_krb5_pa_jwt_req(const krb5_pa_jwt_req *, krb5_data **);

krb5_error_code
encode_krb5_pa_jwt_enc_req(const krb5_data *, krb5_data **);

krb5_error_code
decode_krb5_jwt_tokeninfo(const krb5_data *, krb5_jwt_tokeninfo **);

krb5_error_code
decode_krb5_pa_jwt_challenge(const krb5_data *, krb5_pa_jwt_challenge **);

krb5_error_code
decode_krb5_pa_jwt_req(const krb5_data *, krb5_pa_jwt_req **);

krb5_error_code
decode_krb5_pa_jwt_enc_req(const krb5_data *, krb5_data **);

#endif /* JWT_H */