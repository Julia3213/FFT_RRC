/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "PLMN-IdentityWithOptionalMCC-r6.h"

#include "MCC.h"
asn_TYPE_member_t asn_MBR_PLMN_IdentityWithOptionalMCC_r6_1[] = {
	{ ATF_POINTER, 1, offsetof(struct PLMN_IdentityWithOptionalMCC_r6, mcc),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MCC,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mcc"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PLMN_IdentityWithOptionalMCC_r6, mnc),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MNC,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mnc"
		},
};
static const int asn_MAP_PLMN_IdentityWithOptionalMCC_r6_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PLMN_IdentityWithOptionalMCC_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mcc */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* mnc */
};
asn_SEQUENCE_specifics_t asn_SPC_PLMN_IdentityWithOptionalMCC_r6_specs_1 = {
	sizeof(struct PLMN_IdentityWithOptionalMCC_r6),
	offsetof(struct PLMN_IdentityWithOptionalMCC_r6, _asn_ctx),
	asn_MAP_PLMN_IdentityWithOptionalMCC_r6_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_PLMN_IdentityWithOptionalMCC_r6_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PLMN_IdentityWithOptionalMCC_r6 = {
	"PLMN-IdentityWithOptionalMCC-r6",
	"PLMN-IdentityWithOptionalMCC-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1,
	sizeof(asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1)
		/sizeof(asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1[0]), /* 1 */
	asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1)
		/sizeof(asn_DEF_PLMN_IdentityWithOptionalMCC_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PLMN_IdentityWithOptionalMCC_r6_1,
	2,	/* Elements count */
	&asn_SPC_PLMN_IdentityWithOptionalMCC_r6_specs_1	/* Additional specs */
};

