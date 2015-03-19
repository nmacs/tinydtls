#ifndef _DTLS_ASN1_H_
#define _DTLS_ASN1_H_

#define ASN1_INTEGER            0x02
#define ASN1_BIT_STRING         0x03
#define ASN1_OCTET_STRING       0x04
#define ASN1_NULL               0x05
#define ASN1_PRINTABLE_STR2     0x0C
#define ASN1_OID                0x06
#define ASN1_PRINTABLE_STR2     0x0C
#define ASN1_PRINTABLE_STR      0x13
#define ASN1_TELETEX_STR        0x14
#define ASN1_IA5_STR            0x16
#define ASN1_UTC_TIME           0x17
#define ASN1_GENERALIZED_TIME   0x18
#define ASN1_UNICODE_STR        0x1e
#define ASN1_SEQUENCE           0x30
#define ASN1_CONTEXT_DNSNAME    0x82
#define ASN1_SET                0x31
#define ASN1_V3_DATA            0xa3
#define ASN1_IMPLICIT_TAG       0x80
#define ASN1_CONTEXT_DNSNAME    0x82
#define ASN1_EXPLICIT_TAG       0xa0
#define ASN1_V3_DATA            0xa3

#define SIG_TYPE_MD2            0x02
#define SIG_TYPE_MD5            0x04
#define SIG_TYPE_SHA1           0x05
#define SIG_TYPE_SHA256         0x0b
#define SIG_TYPE_SHA384         0x0c
#define SIG_TYPE_SHA512         0x0d

struct dtls_x509_t;

uint32_t get_asn1_length(const uint8_t *buf, int size, int *offset);
int asn1_next_obj(const uint8_t *buf, int size, int *offset, int obj_type);
int asn1_skip_obj(const uint8_t *buf, int size, int *offset, int obj_type);
int asn1_version(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx);
int asn1_validity(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx);
int asn1_name(const uint8_t *cert, int size, int *offset, char dn[][DTLS_DN_SIZE + 1]);
int asn1_public_key(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx);
int asn1_signature_type(const uint8_t *cert, int size, int *offset, struct dtls_x509_t *x509_ctx);

#endif