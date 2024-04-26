/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SCCPCH-InfoForFACH-r4.h"

static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo__fdd, sib_ReferenceListFACH),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIB_ReferenceListFACH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sib-ReferenceListFACH"
		},
};
static const ber_tlv_tag_t asn_DEF_fdd_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* sib-ReferenceListFACH */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_6 = {
	sizeof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo__fdd),
	offsetof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_6,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_6 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_6,
	sizeof(asn_DEF_fdd_tags_6)
		/sizeof(asn_DEF_fdd_tags_6[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_6,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_6)
		/sizeof(asn_DEF_fdd_tags_6[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_6,
	1,	/* Elements count */
	&asn_SPC_fdd_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_5 = {
	sizeof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo),
	offsetof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo, _asn_ctx),
	offsetof(struct SCCPCH_InfoForFACH_r4__modeSpecificInfo, present),
	sizeof(((struct SCCPCH_InfoForFACH_r4__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_5 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificInfo_constr_5, &asn_PER_type_modeSpecificInfo_constr_5, CHOICE_constraint },
	asn_MBR_modeSpecificInfo_5,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_5	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SCCPCH_InfoForFACH_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4, secondaryCCPCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryCCPCH_Info_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"secondaryCCPCH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4, tfcs),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TFCS,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tfcs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4, fach_PCH_InformationList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FACH_PCH_InformationList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fach-PCH-InformationList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SCCPCH_InfoForFACH_r4, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
};
static const ber_tlv_tag_t asn_DEF_SCCPCH_InfoForFACH_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SCCPCH_InfoForFACH_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* secondaryCCPCH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tfcs */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* fach-PCH-InformationList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* modeSpecificInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_SCCPCH_InfoForFACH_r4_specs_1 = {
	sizeof(struct SCCPCH_InfoForFACH_r4),
	offsetof(struct SCCPCH_InfoForFACH_r4, _asn_ctx),
	asn_MAP_SCCPCH_InfoForFACH_r4_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SCCPCH_InfoForFACH_r4 = {
	"SCCPCH-InfoForFACH-r4",
	"SCCPCH-InfoForFACH-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_SCCPCH_InfoForFACH_r4_tags_1,
	sizeof(asn_DEF_SCCPCH_InfoForFACH_r4_tags_1)
		/sizeof(asn_DEF_SCCPCH_InfoForFACH_r4_tags_1[0]), /* 1 */
	asn_DEF_SCCPCH_InfoForFACH_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_SCCPCH_InfoForFACH_r4_tags_1)
		/sizeof(asn_DEF_SCCPCH_InfoForFACH_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SCCPCH_InfoForFACH_r4_1,
	4,	/* Elements count */
	&asn_SPC_SCCPCH_InfoForFACH_r4_specs_1	/* Additional specs */
};

