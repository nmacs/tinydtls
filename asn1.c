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

#include <stdlib.h>
#include <string.h>

#include "x509.h"
#include "asn1.h"

/* 1.2.840.10045.4.3.2 OID */
static const uint8_t sig_oid[] =
{
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
};

/* CN, O, OU, LVL */
static const uint8_t g_dn_types[] = { 3, 10, 11, 90 };

uint32_t get_asn1_length(const uint8_t *buf, int size, int *offset)
{
	int i;
	uint32_t len;

	if ((*offset + 5) >= size)
		return -1;

	if (!(buf[*offset] & 0x80)) /* short form */
	{
		len = buf[(*offset)++];
	}
	else  /* long form */
	{
		int length_bytes = buf[(*offset)++]&0x7f;
		if (length_bytes > 4)   /* limit number of bytes */
			return -1;

		len = 0;
		for (i = 0; i < length_bytes; i++)
		{
			len <<= 8;
			len += buf[(*offset)++];
		}
	}

	return len;
}

/**
 * Skip the ASN1.1 object type and its length. Get ready to read the object's
 * data.
 */
int asn1_next_obj(const uint8_t *buf, int size, int *offset, int obj_type)
{
	if (*offset >= size)
		return -1;

	if (buf[*offset] != obj_type)
		return -1;

	(*offset)++;
	if (*offset > size)
		return -1;

	return get_asn1_length(buf, size, offset);
}

/**
 * Skip over an ASN.1 object type completely. Get ready to read the next
 * object.
 */
int asn1_skip_obj(const uint8_t *buf, int size, int *offset, int obj_type)
{
	int len;

	if (*offset >= size)
		return -1;

	if (buf[*offset] != obj_type)
		return -1;

	(*offset)++;
	if (*offset > size)
		return -1;

	len = get_asn1_length(buf, size, offset);

	*offset += len;
	if (*offset > size)
		return -1;

	return 0;
}

/**
 * Get the time of a certificate. Ignore hours/minutes/seconds.
 */
static int asn1_get_utc_time(const uint8_t *buf, int size, int *offset, time_t *t)
{
	int ret = -1, len, t_offset, abs_year;
	struct tm tm;

	if (*offset >= size)
		return -1;

	/* see http://tools.ietf.org/html/rfc5280#section-4.1.2.5 */
	if (buf[*offset] == ASN1_UTC_TIME)
	{
		(*offset)++;
		if (*offset > size)
			return -1;

		len = get_asn1_length(buf, size, offset);
		t_offset = *offset;
		if ((t_offset + 5) >= size)
			return -1;

		memset(&tm, 0, sizeof(struct tm));
		tm.tm_year = (buf[t_offset] - '0')*10 + (buf[t_offset+1] - '0');

		if (tm.tm_year <= 50)    /* 1951-2050 thing */
		{
				tm.tm_year += 100;
		}

		tm.tm_mon = (buf[t_offset+2] - '0')*10 + (buf[t_offset+3] - '0') - 1;
		tm.tm_mday = (buf[t_offset+4] - '0')*10 + (buf[t_offset+5] - '0');
		*t = mktime(&tm);
		*offset += len;
		if (*offset > size)
			return -1;
		ret = 0;
	}
	else if (buf[*offset] == ASN1_GENERALIZED_TIME)
	{
		(*offset)++;
		if (*offset > size)
			return -1;

		len = get_asn1_length(buf, size, offset);
		t_offset = *offset;
		if ((t_offset + 13) >= size)
			return -1;

		memset(&tm, 0, sizeof(struct tm));
		abs_year = ((buf[t_offset] - '0')*1000 +
						(buf[t_offset+1] - '0')*100 + (buf[t_offset+2] - '0')*10 +
						(buf[t_offset+3] - '0'));

		if (abs_year <= 1901)
		{
			tm.tm_year = 1;
			tm.tm_mon = 0;
			tm.tm_mday = 1;
		}
		else
		{
			tm.tm_year = abs_year - 1900;
			tm.tm_mon = (buf[t_offset+4] - '0')*10 + (buf[t_offset+5] - '0') - 1;
			tm.tm_mday = (buf[t_offset+6] - '0')*10 + (buf[t_offset+7] - '0');
			tm.tm_hour = (buf[t_offset+8] - '0')*10 + (buf[t_offset+9] - '0');
			tm.tm_min = (buf[t_offset+10] - '0')*10 + (buf[t_offset+11] - '0');
			tm.tm_sec = (buf[t_offset+12] - '0')*10 + (buf[t_offset+13] - '0');
			*t = mktime(&tm);
		}

		*offset += len;
		if (*offset > size)
			return -1;
		ret = 0;
	}

	return ret;
}

/**
 * Get the version type of a certificate (which we don't actually care about)
 */
int asn1_version(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx)
{
	int ret = -1;

	if (*offset >= size)
		return -1;

	(*offset) += 2;        /* get past explicit tag */
	if (asn1_skip_obj(cert, size, offset, ASN1_INTEGER))
		goto end_version;

	ret = 0;
end_version:
	return ret;
}

/**
 * Retrieve the notbefore and notafter certificate times.
 */
int asn1_validity(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx)
{
	if (*offset >= size)
		return -1;
	return (asn1_next_obj(cert, size, offset, ASN1_SEQUENCE) < 0 ||
	        asn1_get_utc_time(cert, size, offset, &x509_ctx->not_before) ||
	        asn1_get_utc_time(cert, size, offset, &x509_ctx->not_after));
}

/**
 * Get the components of a distinguished name 
 */
static int asn1_get_oid_x520(const uint8_t *buf, int size, int *offset)
{
	int dn_type = 0;
	int len;
	
	if (*offset >= size)
		return -1;

	if ((len = asn1_next_obj(buf, size, offset, ASN1_OID)) < 0)
		goto end_oid;

	if ((*offset + 3) > size)
		return -1;

	/* expect a sequence of 2.5.4.[x] where x is a one of distinguished name 
			components we are interested in. */
	if (len == 3 && buf[(*offset)++] == 0x55 && buf[(*offset)++] == 0x04)
		dn_type = buf[(*offset)++];
	else
	{
		*offset += len;     /* skip over it */
	}

	if (*offset > size)
		return -1;

end_oid:
	return dn_type;
}

/**
 * Obtain an ASN.1 printable string type.
 */
static int asn1_get_printable_str(const uint8_t *buf, int size, int *offset, char *str, int length)
{
	int len = -1;
	int asn1_type;

	if (*offset >= size)
		return -1;

	asn1_type = buf[*offset];

	/* some certs have this awful crud in them for some reason */
	if (asn1_type != ASN1_PRINTABLE_STR &&  
					asn1_type != ASN1_PRINTABLE_STR2 &&  
					asn1_type != ASN1_TELETEX_STR &&  
					asn1_type != ASN1_IA5_STR &&  
					asn1_type != ASN1_UNICODE_STR)
			goto end_pnt_str;

	(*offset)++;
	len = get_asn1_length(buf, size, offset);

	/* Check string length */
	if (len > (length - 1))
		goto end_pnt_str;
	
	/* Check buffer length */
	if ((*offset + len) > size)
		return -1;

	if (asn1_type == ASN1_UNICODE_STR)
	{
		/* Unicode strings are not supported. */
		goto end_pnt_str;
	}
	else
	{
		memcpy(str, &buf[*offset], len);
		str[len] = 0;                    /* null terminate */
	}

	*offset += len;
	if (*offset > size)
		return -1;

end_pnt_str:
	return len;
}

/**
 * Get the subject name (or the issuer) of a certificate.
 */
int asn1_name(const uint8_t *cert, int size, int *offset, char dn[][DTLS_DN_SIZE + 1])
{
	int ret = -1;
	int dn_type;
	char tmp[DTLS_DN_SIZE+1];
	
	if (*offset > size)
		return -1;

	if (asn1_next_obj(cert, size, offset, ASN1_SEQUENCE) < 0)
		goto end_name;

	while (asn1_next_obj(cert, size, offset, ASN1_SET) >= 0)
	{
		int i;

		if (asn1_next_obj(cert, size, offset, ASN1_SEQUENCE) < 0 || (dn_type = asn1_get_oid_x520(cert, size, offset)) < 0)
			goto end_name;

		if (asn1_get_printable_str(cert, size, offset, tmp, sizeof(tmp)) < 0)
			goto end_name;

		/* find the distinguished named type */
		for (i = 0; i < X509_NUM_DN_TYPES; i++)
		{
			if (dn_type == g_dn_types[i])
			{
				if (dn[i][0] == '\0')
				{
					strncpy(dn[i], tmp, DTLS_DN_SIZE);
					dn[i][DTLS_DN_SIZE] = 0;
					break;
				}
			}
		}
	}

	ret = 0;
end_name:
	return ret;
}

/**
 * Read the modulus and public exponent of a certificate.
 */
int asn1_public_key(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx)
{
	int ret = -1;
	
	if (*offset >= size)
		return -1;

	if (asn1_next_obj(cert, size, offset, ASN1_SEQUENCE) < 0 ||
	    asn1_skip_obj(cert, size, offset, ASN1_SEQUENCE) ||
	    asn1_next_obj(cert, size, offset, ASN1_BIT_STRING) < 0)
		goto end_pub_key;

	(*offset) += 2;        /* ignore the padding */

	if ((*offset + sizeof(x509_ctx->pub_x) + sizeof(x509_ctx->pub_y)) > size)
		return -1;

	memcpy(x509_ctx->pub_x, &cert[*offset], sizeof(x509_ctx->pub_x));
	(*offset) += sizeof(x509_ctx->pub_x);

	memcpy(x509_ctx->pub_y, &cert[*offset], sizeof(x509_ctx->pub_y));
	(*offset) += sizeof(x509_ctx->pub_y);

	ret = 0;

end_pub_key:
	return ret;
}

/**
 * Read the signature type of the certificate.
 */
int asn1_signature_type(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx)
{
	int ret = -1, len;
	
	if (*offset >= size)
		return -1;

	if (cert[(*offset)++] != ASN1_OID)
		goto end_check_sig;
	
	if (*offset > size)
		return -1;

	len = get_asn1_length(cert, size, offset);
	if ((*offset + len) > size)
		return -1;

	if (len == sizeof(sig_oid) && memcmp(sig_oid, &cert[*offset], sizeof(sig_oid)) == 0) {
		x509_ctx->sig_type = SIG_TYPE_SHA256;
	}
	else {
		goto end_check_sig;     /* unrecognised cert type */
	}

	*offset += len;
	asn1_skip_obj(cert, size, offset, ASN1_NULL); /* if it's there */
	ret = 0;

end_check_sig:
	return ret;
}
