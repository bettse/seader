/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Seader"
 * 	found in "seader.asn1"
 * 	`asn1c -D ./lib/asn1 -no-gen-example -no-gen-OER -no-gen-PER -pdu=all`
 */

#include "NFCRx.h"

asn_TYPE_member_t asn_MBR_NFCRx_1[] = {
	{ ATF_POINTER, 1, offsetof(struct NFCRx, data),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"data"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NFCRx, rfStatus),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RfStatus,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rfStatus"
		},
};
static const ber_tlv_tag_t asn_DEF_NFCRx_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NFCRx_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* data */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* rfStatus */
};
asn_SEQUENCE_specifics_t asn_SPC_NFCRx_specs_1 = {
	sizeof(struct NFCRx),
	offsetof(struct NFCRx, _asn_ctx),
	asn_MAP_NFCRx_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NFCRx = {
	"NFCRx",
	"NFCRx",
	&asn_OP_SEQUENCE,
	asn_DEF_NFCRx_tags_1,
	sizeof(asn_DEF_NFCRx_tags_1)
		/sizeof(asn_DEF_NFCRx_tags_1[0]), /* 1 */
	asn_DEF_NFCRx_tags_1,	/* Same as above */
	sizeof(asn_DEF_NFCRx_tags_1)
		/sizeof(asn_DEF_NFCRx_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NFCRx_1,
	2,	/* Elements count */
	&asn_SPC_NFCRx_specs_1	/* Additional specs */
};

