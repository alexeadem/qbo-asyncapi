#include <libwebsockets.h>


static const char *ecdhes_t1_jose_hdr_es_256 = "{\"alg\":\"ECDH-ES\",\"enc\":\"A256CBC-HS512\"}";

static int auth_ecdhes_t1_enc(struct lws_context *context, const char *jose_hdr, char *ecdhes_t1_plaintext, char *peer_pubkey, size_t len)
{
	char temp[3072], compact[2048];
	int n, ret = -1, temp_len = sizeof(temp);
	struct lws_jwe jwe;

    lwsl_user("peer_pubkey = %s\n", peer_pubkey);

     /* get pub */
	lws_jwe_init(&jwe, context);

	/* encrypt with public */

	/* read and interpret our canned JOSE header, setting the algorithm */
	if (lws_jws_dup_element(&jwe.jws.map, LJWS_JOSE,
				lws_concat_temp(temp, temp_len), &temp_len,
				jose_hdr, strlen(jose_hdr), 0))
		goto done;

	if (lws_jwe_parse_jose(&jwe.jose, jose_hdr, (int)strlen(jose_hdr),
			       temp, &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto done;
	}

	/* for ecdh-es encryption, we need the peer's pubkey */
	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)peer_pubkey,
			   strlen((char *)peer_pubkey)) < 0) {
		lwsl_err("%s: Failed to decode JWK test key\n", __func__);
		goto done;
	}

	/*
	 * dup the plaintext into the ciphertext element, it will be
	 * encrypted in-place to a ciphertext of the same length + padding
	 */
	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				ecdhes_t1_plaintext,
				strlen(ecdhes_t1_plaintext),
				lws_gencrypto_padded_length(LWS_AES_CBC_BLOCKLEN,
						strlen(ecdhes_t1_plaintext)))) {
		lwsl_err("%s: Not enough temp space for ptext\n", __func__);
		goto done;
	}

	/*
	 * perform the actual encryption
	 */
	lwsl_user("perform the actual encryption");
	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len), &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto done;
	}

	/*
	 * format for output
	 */

	lwsl_notice("format for output");
	n = lws_jwe_render_flattened(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n",
			 __func__, n);
		goto done;
	}

	// puts(compact);
	lwsl_notice("render compact");

	n = lws_jwe_render_compact(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n",
			 __func__, n);
		goto done;
	}

	puts(compact);
	//lwsl_hexdump_level(LLL_USER, compact, strlen(compact));
	/* encrypt */

    lwsl_user("compact len = %zu", strlen(compact));
    lwsl_user("ecdhes_t1_plaintext len = %zu", len);

    memcpy(peer_pubkey, compact, len);

	ret = 0;

done:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: %s selftest failed +++++++++++++++++++\n",
			 __func__, jose_hdr);
	else
		lwsl_notice("%s: %s selftest OK\n", __func__, jose_hdr);

	return ret;
}


int main(int argc, const char **argv) {

    struct lws_context_creation_info info;
    struct lws_context *context;
    const char *p;
    int result = 0;

    int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS JOSE api test\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

    context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

    char *aux = "66fac858-a271-49cf-bad0-fdd9ff0b4788";

    char *jwt = "{\"crv\":\"P-521\",\"kty\":\"EC\",\"x\":\"AMu-cWn4gmkQiCAJMeW4BfZUAhPwAA3rROnw6nGUk8hl3bvV7gKKng2Eov6oxTvg70kulH6Nbq2wvJbAzyAjnPlT\",\"y\":\"Ab7VgSfOzG-7IgRF6ffUn5E0J43eDL8_vFtFtP7RihVgNBMUeZzo0yaskfx59SdqnL8q24wEHSTp4dDUxNal3kQ1\"}";

    char buf[1024];
    memset(buf, 0, sizeof(buf));

    lws_snprintf(buf, sizeof(buf), jwt);

    result |= auth_ecdhes_t1_enc(context, ecdhes_t1_jose_hdr_es_256, aux, buf, sizeof(buf));

    lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

    lws_context_destroy(context);

    return 0;
}