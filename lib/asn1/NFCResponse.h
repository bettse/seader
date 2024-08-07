/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Seader"
 * 	found in "seader.asn1"
 * 	`asn1c -D ./lib/asn1 -no-gen-example -no-gen-OER -no-gen-PER -pdu=all`
 */

#ifndef	_NFCResponse_H_
#define	_NFCResponse_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NFCRx.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NFCResponse_PR {
	NFCResponse_PR_NOTHING,	/* No components present */
	NFCResponse_PR_nfcRx,
	NFCResponse_PR_nfcAck
} NFCResponse_PR;

/* NFCResponse */
typedef struct NFCResponse {
	NFCResponse_PR present;
	union NFCResponse_u {
		NFCRx_t	 nfcRx;
		NULL_t	 nfcAck;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NFCResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NFCResponse;
extern asn_CHOICE_specifics_t asn_SPC_NFCResponse_specs_1;
extern asn_TYPE_member_t asn_MBR_NFCResponse_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _NFCResponse_H_ */
#include <asn_internal.h>
