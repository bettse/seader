/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Seader"
 * 	found in "seader.asn1"
 * 	`asn1c -D ./lib/asn1 -no-gen-example -no-gen-OER -no-gen-PER -pdu=all`
 */

#ifndef	_PAC_H_
#define	_PAC_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PAC */
typedef BIT_STRING_t	 PAC_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PAC;
asn_struct_free_f PAC_free;
asn_struct_print_f PAC_print;
asn_constr_check_f PAC_constraint;
ber_type_decoder_f PAC_decode_ber;
der_type_encoder_f PAC_encode_der;
xer_type_decoder_f PAC_decode_xer;
xer_type_encoder_f PAC_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _PAC_H_ */
#include <asn_internal.h>
