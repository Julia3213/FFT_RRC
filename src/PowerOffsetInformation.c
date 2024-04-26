/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "PowerOffsetInformation.h"

asn_TYPE_member_t asn_MBR_PowerOffsetInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PowerOffsetInformation, gainFactorInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_GainFactorInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gainFactorInformation"
		},
	{ ATF_POINTER, 1, offsetof(struct PowerOffsetInformation, powerOffsetPp_m),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PowerOffsetPp_m,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"powerOffsetPp-m"
		},
};
static const int asn_MAP_PowerOffsetInformation_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_PowerOffsetInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PowerOffsetInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gainFactorInformation */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* powerOffsetPp-m */
};
asn_SEQUENCE_specifics_t asn_SPC_PowerOffsetInformation_specs_1 = {
	sizeof(struct PowerOffsetInformation),
	offsetof(struct PowerOffsetInformation, _asn_ctx),
	asn_MAP_PowerOffsetInformation_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_PowerOffsetInformation_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PowerOffsetInformation = {
	"PowerOffsetInformation",
	"PowerOffsetInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_PowerOffsetInformation_tags_1,
	sizeof(asn_DEF_PowerOffsetInformation_tags_1)
		/sizeof(asn_DEF_PowerOffsetInformation_tags_1[0]), /* 1 */
	asn_DEF_PowerOffsetInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_PowerOffsetInformation_tags_1)
		/sizeof(asn_DEF_PowerOffsetInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PowerOffsetInformation_1,
	2,	/* Elements count */
	&asn_SPC_PowerOffsetInformation_specs_1	/* Additional specs */
};

