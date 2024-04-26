/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-DPCH-InfoCommonPredef.h"

static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__fdd, spreadingFactorAndPilot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SF512_AndPilot,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spreadingFactorAndPilot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__fdd, positionFixedOrFlexible),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PositionFixedOrFlexible,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"positionFixedOrFlexible"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__fdd, tfci_Existence),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tfci-Existence"
		},
};
static const ber_tlv_tag_t asn_DEF_fdd_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* spreadingFactorAndPilot */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* positionFixedOrFlexible */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* tfci-Existence */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_3 = {
	sizeof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__fdd),
	offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_3,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_3 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_3,
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_3,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_3,
	3,	/* Elements count */
	&asn_SPC_fdd_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__tdd, commonTimeslotInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CommonTimeslotInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"commonTimeslotInfo"
		},
};
static const ber_tlv_tag_t asn_DEF_tdd_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* commonTimeslotInfo */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_7 = {
	sizeof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__tdd),
	offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_7,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_7 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_7,
	sizeof(asn_DEF_tdd_tags_7)
		/sizeof(asn_DEF_tdd_tags_7[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_7,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_7)
		/sizeof(asn_DEF_tdd_tags_7[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_7,
	1,	/* Elements count */
	&asn_SPC_tdd_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_2 = {
	sizeof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo),
	offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo, _asn_ctx),
	offsetof(struct DL_DPCH_InfoCommonPredef__modeSpecificInfo, present),
	sizeof(((struct DL_DPCH_InfoCommonPredef__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_2 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificInfo_constr_2, &asn_PER_type_modeSpecificInfo_constr_2, CHOICE_constraint },
	asn_MBR_modeSpecificInfo_2,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DL_DPCH_InfoCommonPredef_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoCommonPredef, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
};
static const ber_tlv_tag_t asn_DEF_DL_DPCH_InfoCommonPredef_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_DPCH_InfoCommonPredef_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* modeSpecificInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_DPCH_InfoCommonPredef_specs_1 = {
	sizeof(struct DL_DPCH_InfoCommonPredef),
	offsetof(struct DL_DPCH_InfoCommonPredef, _asn_ctx),
	asn_MAP_DL_DPCH_InfoCommonPredef_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_DPCH_InfoCommonPredef = {
	"DL-DPCH-InfoCommonPredef",
	"DL-DPCH-InfoCommonPredef",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_DPCH_InfoCommonPredef_tags_1,
	sizeof(asn_DEF_DL_DPCH_InfoCommonPredef_tags_1)
		/sizeof(asn_DEF_DL_DPCH_InfoCommonPredef_tags_1[0]), /* 1 */
	asn_DEF_DL_DPCH_InfoCommonPredef_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_DPCH_InfoCommonPredef_tags_1)
		/sizeof(asn_DEF_DL_DPCH_InfoCommonPredef_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_DPCH_InfoCommonPredef_1,
	1,	/* Elements count */
	&asn_SPC_DL_DPCH_InfoCommonPredef_specs_1	/* Additional specs */
};

