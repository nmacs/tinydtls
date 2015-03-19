/*
 * Copyright (c) 2007-2015, Cameron Rich
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 * * Neither the name of the axTLS project nor the names of its contributors 
 *   may be used to endorse or promote products derived from this software 
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tinydtls.h"
#include "dtls_config.h"
#include "x509.h"
#include "asn1.h"

/**
 * Construct a new x509 object.
 * @return 0 if ok. < 0 if there was a problem.
 */
int dtls_x509_parse(struct dtls_x509_t *ctx, const uint8_t *cert, int *len)
{
	int begin_tbs, end_tbs;
	int ret = -1, offset = 0, cert_size = 0;
	int size = *len;
	struct dtls_x509_t *x509_ctx = ctx;

	/* get the certificate size */
	asn1_skip_obj(cert, size, &cert_size, ASN1_SEQUENCE);

	if (len && cert_size != size)
		return -1;

	if (asn1_next_obj(cert, size, &offset, ASN1_SEQUENCE) < 0)
		goto end_cert;
	
	begin_tbs = offset;         /* start of the tbs */
	end_tbs = begin_tbs;        /* work out the end of the tbs */
	asn1_skip_obj(cert, size, &end_tbs, ASN1_SEQUENCE);

	if (asn1_next_obj(cert, size, &offset, ASN1_SEQUENCE) < 0)
		goto end_cert;

	if (offset >= size)
		goto end_cert;

	if (cert[offset] == ASN1_EXPLICIT_TAG)   /* optional version */
	{
		if (asn1_version(cert, size, &offset, x509_ctx))
			goto end_cert;
	}

	if (asn1_skip_obj(cert, size, &offset, ASN1_INTEGER) || /* serial number */
	    asn1_next_obj(cert, size, &offset, ASN1_SEQUENCE) < 0)
	{
		goto end_cert;
	}

	/* make sure the signature is ok */
	if (asn1_signature_type(cert, size, &offset, x509_ctx))
	{
		ret = -1;
		goto end_cert;
	}

	if (asn1_name(cert, size, &offset, x509_ctx->ca_cert_dn) ||
					asn1_validity(cert, size, &offset, x509_ctx) ||
					asn1_name(cert, size, &offset, x509_ctx->cert_dn) ||
					asn1_public_key(cert, size, &offset, x509_ctx))
	{
		goto end_cert;
	}

	x509_ctx->begin_tbs = begin_tbs;
	x509_ctx->end_tbs = end_tbs;
	if (len)
		*len = end_tbs - begin_tbs;
	ret = 0;

end_cert:
	return ret;
}

static const char *not_part_of_cert = "<Not Part Of Certificate>";
void dtls_x509_print(const struct dtls_x509_t *cert)
{
    if (cert == NULL)
        return;

    printf("=== CERTIFICATE ISSUED TO ===\n");
    printf("Common Name (CN):\t\t");
    printf("%s\n", cert->cert_dn[X509_COMMON_NAME][0] ?
                    cert->cert_dn[X509_COMMON_NAME] : not_part_of_cert);

    printf("Organization (O):\t\t");
    printf("%s\n", cert->cert_dn[X509_ORGANIZATION][0] ?
        cert->cert_dn[X509_ORGANIZATION] : not_part_of_cert);

    printf("Organizational Unit (OU):\t");
    printf("%s\n", cert->cert_dn[X509_ORGANIZATIONAL_UNIT][0] ?
        cert->cert_dn[X509_ORGANIZATIONAL_UNIT] : not_part_of_cert);

    printf("Access Level (LVL):\t");
    printf("%s\n", cert->cert_dn[X509_ACCESS_LEVEL][0] ?
        cert->cert_dn[X509_ACCESS_LEVEL] : not_part_of_cert);

    printf("=== CERTIFICATE ISSUED BY ===\n");
    printf("Common Name (CN):\t\t");
    printf("%s\n", cert->ca_cert_dn[X509_COMMON_NAME][0] ?
                    cert->ca_cert_dn[X509_COMMON_NAME] : not_part_of_cert);

    printf("Organization (O):\t\t");
    printf("%s\n", cert->ca_cert_dn[X509_ORGANIZATION][0] ?
        cert->ca_cert_dn[X509_ORGANIZATION] : not_part_of_cert);

    printf("Organizational Unit (OU):\t");
    printf("%s\n", cert->ca_cert_dn[X509_ORGANIZATIONAL_UNIT][0] ?
        cert->ca_cert_dn[X509_ORGANIZATIONAL_UNIT] : not_part_of_cert);

    printf("Not Before:\t\t\t%s", ctime(&cert->not_before));
    printf("Not After:\t\t\t%s", ctime(&cert->not_after));
    printf("Sig Type:\t\t\t");
    switch (cert->sig_type)
    {
        case SIG_TYPE_MD2:
            printf("MD2\n");
            break;
        case SIG_TYPE_MD5:
            printf("MD5\n");
            break;
        case SIG_TYPE_SHA1:
            printf("SHA1\n");
            break;
        case SIG_TYPE_SHA256:
            printf("SHA256\n");
            break;
        case SIG_TYPE_SHA384:
            printf("SHA384\n");
            break;
        case SIG_TYPE_SHA512:
            printf("SHA512\n");
            break;
        default:
            printf("Unrecognized: %d\n", cert->sig_type);
            break;
    }
}