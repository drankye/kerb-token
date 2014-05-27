/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/jwt/jwt_srv.c - OTP kdcpreauth module definition */
/*
 * Copyright 2011 NORDUnet A/S.  All rights reserved.
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

#include "k5-int.h"
#include <krb5/preauth_plugin.h>
#include <k5-json.h>
#include "jwt.h"

#include <errno.h>
#include <ctype.h>

static krb5_preauthtype jwt_pa_type_list[] =
  { KRB5_PADATA_JWT_REQUEST, 0 };

static void
kdc_context_free(jwt_kdc_context *jwtctx)
{
    if (jwtctx == NULL)
        return;

    free(jwtctx->vendor);
    free(jwtctx);
}

static krb5_error_code
kdc_context_new(krb5_context ctx, jwt_kdc_context **out)
{
    jwt_kdc_context *jwtctx;

    jwtctx = calloc(1, sizeof(jwt_kdc_context));
    if (jwtctx == NULL)
        return ENOMEM;

    jwtctx->vendor = strdup("jwt");

    *out = jwtctx;
    return 0;
}

static krb5_error_code
token_verify(krb5_context ctx, krb5_keyblock *armor_key,
             krb5_data *token, const char *config)
{
    krb5_error_code retval = 0;

    if (armor_key == NULL || token == NULL) {
        retval = EINVAL;
    }

	// todo: very the token according to the spec

	return retval;
}

static krb5_error_code
jwt_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames)
{
    krb5_error_code retval;
    jwt_kdc_context *jwtctx;

    retval = kdc_context_new(context, &jwtctx);
    if (retval)
        return retval;
    *moddata_out = (krb5_kdcpreauth_moddata)jwtctx;

    return 0;
}

static void
jwt_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    kdc_context_free((jwt_kdc_context *)moddata);
}

static int
jwt_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_SUFFICIENT | PA_REPLACES_KEY;
}

static void
jwt_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
    jwt_kdc_context *jwtctx;
    krb5_jwt_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_keyblock *armor_key = NULL;
    krb5_pa_jwt_challenge chl;
    krb5_pa_data *pa = NULL;
    krb5_error_code retval = 0;
    krb5_data *encoding;

    /* Determine if jwt is enabled for the user. */
    jwtctx = (jwt_kdc_context*) moddata;
    if (jwtctx == NULL)
        goto out; 

    /* Get the armor key.  This indicates the length of random data to use in
     * the nonce. */
    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = ENOENT;
        goto out;
    }

    /* Build the (mostly empty) challenge. */
    memset(&ti, 0, sizeof(ti));
    memset(&chl, 0, sizeof(chl));
    chl.tokeninfo = tis;
    ti.vendor.data = strdup(jwtctx->vendor);
    ti.vendor.length = strlen(jwtctx->vendor);

    /* Build the output pa-data. */
    retval = encode_krb5_pa_jwt_challenge(&chl, &encoding);
    if (retval != 0)
        goto out;
    pa = k5alloc(sizeof(krb5_pa_data), &retval);
    if (pa == NULL) {
        krb5_free_data(context, encoding);
        goto out;
    }
    pa->pa_type = KRB5_PADATA_JWT_CHALLENGE;
    pa->contents = (krb5_octet *)encoding->data;
    pa->length = encoding->length;
    free(encoding);

out:
    (*respond)(arg, retval, pa);
}

static krb5_data*
jwt_authz_data(krb5_context context, krb5_pa_jwt_req *req)
{
    krb5_error_code retval;
	krb5_authdata **authz_data = NULL;
    krb5_data *ad_if_relevant;

    authz_data = (krb5_authdata **)calloc(2, sizeof(krb5_authdata *));
    if (authz_data == NULL) {
        return NULL;
    }
    authz_data[1] = NULL;
    authz_data[0] = (krb5_authdata *)malloc(sizeof(krb5_authdata));
    authz_data[0]->contents = malloc(req->token.length + 1);
    if (authz_data[0]->contents == NULL) {
        free(authz_data);
        return NULL;
    }
    memset(authz_data[0]->contents, '\0', req->token.length + 1);
    authz_data[0]->magic = KV5M_AUTHDATA;
    authz_data[0]->ad_type = KRB5_AUTHDATA_JWT;
    authz_data[0]->length = req->token.length;
    memcpy(authz_data[0]->contents, req->token.data, req->token.length);

    retval = encode_krb5_authdata(authz_data, &ad_if_relevant);
    if (retval) {
        free(authz_data[0]->contents);
        free(authz_data);
        return NULL;
    }

    return ad_if_relevant;
}

static void
jwt_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
           krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata,
           krb5_kdcpreauth_verify_respond_fn respond, void *arg)
{
    krb5_keyblock *armor_key = NULL;
    krb5_pa_jwt_req *req = NULL;
    krb5_error_code retval;
    krb5_data d;
    krb5_authdata **authz_container = NULL;
    krb5_data *ad_if_relevant;
    //char *config;

    /* Get the FAST armor key. */
    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        com_err("jwt", retval, "No armor key found when verifying padata");
        goto error;
    }

    /* Decode the request. */
    d = make_data(pa->contents, pa->length);
    retval = decode_krb5_pa_jwt_req(&d, &req);
    if (retval != 0) {
        com_err("jwt", retval, "Unable to decode JWT request");
        goto error;
    }

    /* Get the principal's JWT configuration string. */
    /*
    retval = cb->get_string(context, rock, "jwt", &config);
    if (retval == 0 && config == NULL)
        retval = KRB5_PREAUTH_FAILED;
    if (retval != 0) {
        goto error;
    }*/

	/* Verify the token. */
    retval = token_verify(context, armor_key, &req->token, NULL);
    if (retval != 0) {
        com_err("jwt", retval, "Unable to verify the token");
        goto error;
    }

    /*
     * Return the authorization data that contains the token
     */
    ad_if_relevant = jwt_authz_data(context, req);
    if (ad_if_relevant == NULL) {
        goto error;
    }

    /* Wrap in AD-IF-RELEVANT container */
    authz_container = (krb5_authdata **)calloc(2, sizeof(krb5_authdata *));
    if (authz_container == NULL)
        goto error;

    authz_container[1] = NULL;
    authz_container[0] = malloc(sizeof(krb5_authdata));
    if (authz_container[0] == NULL) {
        free(authz_container);
        goto error;
    }
    authz_container[0]->magic = KV5M_AUTHDATA;
    authz_container[0]->ad_type = KRB5_AUTHDATA_IF_RELEVANT;
    authz_container[0]->length = ad_if_relevant->length;
    authz_container[0]->contents = (krb5_octet *)ad_if_relevant->data;
    free(ad_if_relevant);

    /* Note that preauthentication succeeded. */
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;

    (*respond)(arg, 0, (krb5_kdcpreauth_modreq)NULL, NULL, authz_container);


    //cb->free_string(context, rock, config);
    k5_free_pa_jwt_req(context, req);
    return;

error:
    k5_free_pa_jwt_req(context, req);
    (*respond)(arg, retval, NULL, NULL, NULL);
}

static krb5_error_code
jwt_return_padata(krb5_context context, krb5_pa_data *padata,
                  krb5_data *req_pkt, krb5_kdc_req *request,
                  krb5_kdc_rep *reply, krb5_keyblock *encrypting_key,
                  krb5_pa_data **send_pa_out, krb5_kdcpreauth_callbacks cb,
                  krb5_kdcpreauth_rock rock, krb5_kdcpreauth_moddata moddata,
                  krb5_kdcpreauth_modreq modreq)
{
    krb5_keyblock *armor_key = NULL;

    if (padata->length == 0)
        return 0;

    /* Get the armor key. */
    armor_key = cb->fast_armor(context, rock);
    if (!armor_key) {
      com_err("jwt", ENOENT, "No armor key found when returning padata");
      return ENOENT;
    }

    /* Replace the reply key with the FAST armor key. */
    krb5_free_keyblock_contents(context, encrypting_key);
    return krb5_copy_keyblock_contents(context, armor_key, encrypting_key);
}

krb5_error_code
kdcpreauth_jwt_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable);

krb5_error_code
kdcpreauth_jwt_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable)
{
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = "jwt";
    vt->pa_type_list = jwt_pa_type_list;
    vt->init = jwt_init;
    vt->fini = jwt_fini;
    vt->flags = jwt_flags;
    vt->edata = jwt_edata;
    vt->verify = jwt_verify;
    vt->return_padata = jwt_return_padata;

    com_err("jwt", 0, "Loaded");

    return 0;
}

