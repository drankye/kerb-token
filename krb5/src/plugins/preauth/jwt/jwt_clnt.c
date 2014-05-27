/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/preauth_jwt.c - JWT clpreauth module */
/*
 * Copyright 2011 NORDUnet A/S.  All rights reserved.
 * Copyright 2011 Red Hat, Inc.  All rights reserved.
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

#include "k5-int.h"
#include "k5-json.h"
#include "jwt.h"

#include <krb5/clpreauth_plugin.h>
#include <ctype.h>

static krb5_preauthtype jwt_client_supported_pa_types[] =
    { KRB5_PADATA_JWT_CHALLENGE, 0 };

static void
context_free(jwt_context *jwtctx)
{
    if (jwtctx == NULL)
        return;

    free(jwtctx->vendor);
    free(jwtctx->token);
    free(jwtctx);
}

static krb5_error_code
context_new(krb5_context ctx, jwt_context **out)
{
    jwt_context *jwtctx;

    jwtctx = calloc(1, sizeof(jwt_context));
    if (jwtctx == NULL)
        return ENOMEM;

    jwtctx->vendor = NULL;
    jwtctx->token = NULL;

    *out = jwtctx;
    return 0;
}

static int
jwt_client_plugin_init(krb5_context context,
                          krb5_clpreauth_moddata *moddata_out)
{
    krb5_error_code retval = 0;
    jwt_context *ctx = NULL;

    context_new(context, &ctx);

    *moddata_out = (krb5_clpreauth_moddata)ctx;
    return retval;
}

static void
jwt_client_plugin_fini(krb5_context context, krb5_clpreauth_moddata moddata)
{
    jwt_context *ctx = (jwt_context*)moddata;

    if (ctx == NULL) {
        return;
    }

    context_free(ctx);
}

/* Builds a request using the specified tokeninfo. */
static krb5_error_code
make_request(krb5_context ctx, jwt_context *jwtctx, krb5_pa_jwt_req **out_req)
{
    krb5_pa_jwt_req *req = NULL;
    krb5_error_code retval = 0;

    req = calloc(1, sizeof(krb5_pa_jwt_req));
    if (req == NULL)
        return ENOMEM;

    retval = krb5int_copy_data_contents(ctx, jwtctx->vendor, &req->vendor);
    if (retval != 0)
        goto error;
    
    req->token.data = strdup(jwtctx->token);
    req->token.length = strlen(jwtctx->token);

    *out_req = req;
    return 0;

error:
    k5_free_pa_jwt_req(ctx, req);
    return retval;
}

/* Encode the JWT request into a krb5_pa_data buffer. */
static krb5_error_code
set_pa_data(const krb5_pa_jwt_req *req, krb5_pa_data ***pa_data_out)
{
    krb5_pa_data **out = NULL;
    krb5_data *tmp;

    /* Allocate the preauth data array and one item. */
    out = calloc(2, sizeof(krb5_pa_data *));
    if (out == NULL)
        goto error;
    out[0] = calloc(1, sizeof(krb5_pa_data));
    out[1] = NULL;
    if (out[0] == NULL)
        goto error;

    /* Encode our request into the preauth data item. */
    memset(out[0], 0, sizeof(krb5_pa_data));
    out[0]->pa_type = KRB5_PADATA_JWT_REQUEST;
    if (encode_krb5_pa_jwt_req(req, &tmp) != 0)
        goto error;
    out[0]->contents = (krb5_octet *)tmp->data;
    out[0]->length = tmp->length;

    *pa_data_out = out;
    return 0;

error:
    if (out != NULL) {
        free(out[0]);
        free(out);
    }
    return ENOMEM;
}

/*
 * Save the token info to the
 * out_ccache, so that later we can try to use them to select the right one
 * without having ot ask the user.
 */
static void
save_config_tokeninfo(krb5_context context,
                      krb5_clpreauth_callbacks cb,
                      krb5_clpreauth_rock rock,
                      krb5_jwt_tokeninfo *ti)
{
	cb->set_cc_config(context, rock, "token", ti->vendor.data);
}

static void
jwt_client_request_init(krb5_context context, krb5_clpreauth_moddata moddata,
                        krb5_clpreauth_modreq *modreq_out)
{
    *modreq_out = calloc(1, sizeof(krb5_pa_jwt_challenge *));
}

static krb5_error_code
jwt_client_process(krb5_context context, krb5_clpreauth_moddata moddata,
                   krb5_clpreauth_modreq modreq, krb5_get_init_creds_opt *opt,
                   krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
                   krb5_kdc_req *request, krb5_data *encoded_request_body,
                   krb5_data *encoded_previous_request, krb5_pa_data *pa_data,
                   krb5_prompter_fct prompter, void *prompter_data,
                   krb5_pa_data ***pa_data_out)
{
    jwt_context *jwtctx = (jwt_context*)moddata;
    //krb5_pa_jwt_challenge *chl = NULL;
    krb5_jwt_tokeninfo *ti = NULL;
    krb5_keyblock *as_key = NULL;
    krb5_pa_jwt_req *req = NULL;
    krb5_error_code retval = 0;

    if (modreq == NULL)
        return ENOMEM;
    //chl = *(krb5_pa_jwt_challenge **)modreq;

    *pa_data_out = NULL;

    /* Get FAST armor key. */
    as_key = cb->fast_armor(context, rock);
    if (as_key == NULL)
        return ENOENT;

    /* Use FAST armor key as response key. */
    retval = cb->set_as_key(context, rock, as_key);
    if (retval != 0)
        return retval;

    /* Attempt to get token info. */
	//ti = chl->tokeninfo[0]; //ZKTODO

    /* Make the request. */
    retval = make_request(context, jwtctx, &req);
    if (retval != 0)
        goto error;

    /* Save information about the token which was used. */
    //save_config_tokeninfo(context, cb, rock, ti);

    /* Encode the request into the pa_data output. */
    retval = set_pa_data(req, pa_data_out);
    return retval;

error:
    k5_free_pa_jwt_req(context, req);
    return retval;
}

static void
jwt_client_request_fini(krb5_context context, krb5_clpreauth_moddata moddata,
                        krb5_clpreauth_modreq modreq)
{
    if (modreq == NULL)
        return;

    k5_free_pa_jwt_challenge(context, *(krb5_pa_jwt_challenge **)modreq);
    free(modreq);
}

static krb5_error_code
handle_gic_opt(krb5_context context,
               jwt_context *jwtctx,
               const char *attr,
               const char *value)
{    
    if (strcmp(attr, "token") == 0) {
        jwtctx->token = strdup(value);
        jwtctx->vendor = strdup("jwt");
    }
    return 0;
}

static krb5_error_code
jwt_client_gic_opt(krb5_context context, krb5_clpreauth_moddata moddata,
                      krb5_get_init_creds_opt *gic_opt,
                      const char *attr,
                      const char *value)
{
    krb5_error_code retval;
    jwt_context *jwtctx = (jwt_context*)moddata;

    retval = handle_gic_opt(context, jwtctx, attr, value);
    if (retval)
        return retval;

    return 0;
}

krb5_error_code
clpreauth_jwt_initvt(krb5_context context, int maj_ver, int min_ver,
                        krb5_plugin_vtable vtable);

krb5_error_code
clpreauth_jwt_initvt(krb5_context context, int maj_ver, int min_ver,
                     krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = "jwt";
    vt->pa_type_list = jwt_client_supported_pa_types;
    vt->init = jwt_client_plugin_init;
    vt->fini = jwt_client_plugin_fini;
    vt->request_init = jwt_client_request_init;
    // vt->prep_questions = jwt_client_prep_questions;
    vt->process = jwt_client_process;
    vt->request_fini = jwt_client_request_fini;
    vt->gic_opts = jwt_client_gic_opt;

    return 0;
}
