/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "E-HICH-Information.h"

asn_TYPE_member_t asn_MBR_E_HICH_Information_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_HICH_Information, channelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_HICH_ChannelisationCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelisationCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_HICH_Information, signatureSequence),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_HICH_RGCH_SignatureSequence,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"signatureSequence"
		},
};
static const ber_tlv_tag_t asn_DEF_E_HICH_Information_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_E_HICH_Information_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* channelisationCode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* signatureSequence */
};
asn_SEQUENCE_specifics_t asn_SPC_E_HICH_Information_specs_1 = {
	sizeof(struct E_HICH_Information),
	offsetof(struct E_HICH_Information, _asn_ctx),
	asn_MAP_E_HICH_Information_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_E_HICH_Information = {
	"E-HICH-Information",
	"E-HICH-Information",
	&asn_OP_SEQUENCE,
	asn_DEF_E_HICH_Information_tags_1,
	sizeof(asn_DEF_E_HICH_Information_tags_1)
		/sizeof(asn_DEF_E_HICH_Information_tags_1[0]), /* 1 */
	asn_DEF_E_HICH_Information_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_HICH_Information_tags_1)
		/sizeof(asn_DEF_E_HICH_Information_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_E_HICH_Information_1,
	2,	/* Elements count */
	&asn_SPC_E_HICH_Information_specs_1	/* Additional specs */
};

