#ifndef _DTLS_X509_H_
#define _DTLS_X509_H_

#include <time.h>
#include <stdint.h>

#define DTLS_DN_SIZE                        15

/*
 * The Distinguished Name
 */
#define X509_NUM_DN_TYPES                   4
#define X509_COMMON_NAME                    0
#define X509_ORGANIZATION                   1
#define X509_ORGANIZATIONAL_UNIT            2
#define X509_ACCESS_LEVEL                   3

struct dtls_x509_t
{
	char ca_cert_dn[X509_NUM_DN_TYPES][DTLS_DN_SIZE + 1];
	char cert_dn[X509_NUM_DN_TYPES][DTLS_DN_SIZE + 1];
	time_t not_before;
	time_t not_after;
	uint8_t sig_type;

	int begin_tbs;
	int end_tbs;

	uint8_t pub_x[32];
	uint8_t pub_y[32];
};

static inline const char* dtls_x509_get_common_name(const struct dtls_x509_t* ctx)
{
	return ctx->cert_dn[X509_COMMON_NAME];
}

static inline const char* dtls_x509_get_access_level(const struct dtls_x509_t* ctx)
{
	return ctx->cert_dn[X509_ACCESS_LEVEL];
}

int dtls_x509_parse(struct dtls_x509_t *ctx, const uint8_t *cert, int *len);
void x509_print(const struct dtls_x509_t *cert);

#endif