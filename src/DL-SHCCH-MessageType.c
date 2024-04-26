/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Class-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-SHCCH-MessageType.h"

static asn_oer_constraints_t asn_OER_type_DL_SHCCH_MessageType_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_DL_SHCCH_MessageType_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_DL_SHCCH_MessageType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_SHCCH_MessageType, choice.physicalSharedChannelAllocation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PhysicalSharedChannelAllocation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"physicalSharedChannelAllocation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_SHCCH_MessageType, choice.spare),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_DL_SHCCH_MessageType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* physicalSharedChannelAllocation */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* spare */
};
asn_CHOICE_specifics_t asn_SPC_DL_SHCCH_MessageType_specs_1 = {
	sizeof(struct DL_SHCCH_MessageType),
	offsetof(struct DL_SHCCH_MessageType, _asn_ctx),
	offsetof(struct DL_SHCCH_MessageType, present),
	sizeof(((struct DL_SHCCH_MessageType *)0)->present),
	asn_MAP_DL_SHCCH_MessageType_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_DL_SHCCH_MessageType = {
	"DL-SHCCH-MessageType",
	"DL-SHCCH-MessageType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_DL_SHCCH_MessageType_constr_1, &asn_PER_type_DL_SHCCH_MessageType_constr_1, CHOICE_constraint },
	asn_MBR_DL_SHCCH_MessageType_1,
	2,	/* Elements count */
	&asn_SPC_DL_SHCCH_MessageType_specs_1	/* Additional specs */
};

