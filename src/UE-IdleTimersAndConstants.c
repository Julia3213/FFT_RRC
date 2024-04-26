/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-IdleTimersAndConstants.h"

asn_TYPE_member_t asn_MBR_UE_IdleTimersAndConstants_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_IdleTimersAndConstants, t_300),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_T_300,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t-300"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_IdleTimersAndConstants, n_300),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_N_300,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"n-300"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_IdleTimersAndConstants, t_312),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_T_312,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t-312"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_IdleTimersAndConstants, n_312),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_N_312,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"n-312"
		},
};
static const ber_tlv_tag_t asn_DEF_UE_IdleTimersAndConstants_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_IdleTimersAndConstants_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* t-300 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* n-300 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* t-312 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* n-312 */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_IdleTimersAndConstants_specs_1 = {
	sizeof(struct UE_IdleTimersAndConstants),
	offsetof(struct UE_IdleTimersAndConstants, _asn_ctx),
	asn_MAP_UE_IdleTimersAndConstants_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_IdleTimersAndConstants = {
	"UE-IdleTimersAndConstants",
	"UE-IdleTimersAndConstants",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_IdleTimersAndConstants_tags_1,
	sizeof(asn_DEF_UE_IdleTimersAndConstants_tags_1)
		/sizeof(asn_DEF_UE_IdleTimersAndConstants_tags_1[0]), /* 1 */
	asn_DEF_UE_IdleTimersAndConstants_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_IdleTimersAndConstants_tags_1)
		/sizeof(asn_DEF_UE_IdleTimersAndConstants_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_IdleTimersAndConstants_1,
	4,	/* Elements count */
	&asn_SPC_UE_IdleTimersAndConstants_specs_1	/* Additional specs */
};

