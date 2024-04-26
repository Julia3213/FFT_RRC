/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RLC-InfoChoice-r6.h"

static asn_oer_constraints_t asn_OER_type_RLC_InfoChoice_r6_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RLC_InfoChoice_r6_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RLC_InfoChoice_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RLC_InfoChoice_r6, choice.rlc_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RLC_Info_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rlc-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RLC_InfoChoice_r6, choice.same_as_RB),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"same-as-RB"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RLC_InfoChoice_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rlc-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* same-as-RB */
};
asn_CHOICE_specifics_t asn_SPC_RLC_InfoChoice_r6_specs_1 = {
	sizeof(struct RLC_InfoChoice_r6),
	offsetof(struct RLC_InfoChoice_r6, _asn_ctx),
	offsetof(struct RLC_InfoChoice_r6, present),
	sizeof(((struct RLC_InfoChoice_r6 *)0)->present),
	asn_MAP_RLC_InfoChoice_r6_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RLC_InfoChoice_r6 = {
	"RLC-InfoChoice-r6",
	"RLC-InfoChoice-r6",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RLC_InfoChoice_r6_constr_1, &asn_PER_type_RLC_InfoChoice_r6_constr_1, CHOICE_constraint },
	asn_MBR_RLC_InfoChoice_r6_1,
	2,	/* Elements count */
	&asn_SPC_RLC_InfoChoice_r6_specs_1	/* Additional specs */
};

