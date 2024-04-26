/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "AlgorithmSpecificInfo-r4.h"

static asn_oer_constraints_t asn_OER_type_AlgorithmSpecificInfo_r4_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_AlgorithmSpecificInfo_r4_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_AlgorithmSpecificInfo_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AlgorithmSpecificInfo_r4, choice.rfc2507_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RFC2507_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rfc2507-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AlgorithmSpecificInfo_r4, choice.rfc3095_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RFC3095_Info_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rfc3095-Info"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_AlgorithmSpecificInfo_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rfc2507-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* rfc3095-Info */
};
asn_CHOICE_specifics_t asn_SPC_AlgorithmSpecificInfo_r4_specs_1 = {
	sizeof(struct AlgorithmSpecificInfo_r4),
	offsetof(struct AlgorithmSpecificInfo_r4, _asn_ctx),
	offsetof(struct AlgorithmSpecificInfo_r4, present),
	sizeof(((struct AlgorithmSpecificInfo_r4 *)0)->present),
	asn_MAP_AlgorithmSpecificInfo_r4_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_AlgorithmSpecificInfo_r4 = {
	"AlgorithmSpecificInfo-r4",
	"AlgorithmSpecificInfo-r4",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_AlgorithmSpecificInfo_r4_constr_1, &asn_PER_type_AlgorithmSpecificInfo_r4_constr_1, CHOICE_constraint },
	asn_MBR_AlgorithmSpecificInfo_r4_1,
	2,	/* Elements count */
	&asn_SPC_AlgorithmSpecificInfo_r4_specs_1	/* Additional specs */
};
