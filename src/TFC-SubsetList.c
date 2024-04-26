/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TFC-SubsetList.h"

#include "TFCS-Identity.h"
static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_TFC_SubsetList_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..1024)) */};
asn_per_constraints_t asn_PER_type_TFC_SubsetList_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 10,  10,  1,  1024 }	/* (SIZE(1..1024)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_tdd_5[] = {
	{ ATF_POINTER, 1, offsetof(struct TFC_SubsetList__Member__modeSpecificInfo__tdd, tfcs_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TFCS_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tfcs-ID"
		},
};
static const int asn_MAP_tdd_oms_5[] = { 0 };
static const ber_tlv_tag_t asn_DEF_tdd_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* tfcs-ID */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_5 = {
	sizeof(struct TFC_SubsetList__Member__modeSpecificInfo__tdd),
	offsetof(struct TFC_SubsetList__Member__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_5,
	1,	/* Count of tags in the map */
	asn_MAP_tdd_oms_5,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_5 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_5,
	sizeof(asn_DEF_tdd_tags_5)
		/sizeof(asn_DEF_tdd_tags_5[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_5,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_5)
		/sizeof(asn_DEF_tdd_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_5,
	1,	/* Elements count */
	&asn_SPC_tdd_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TFC_SubsetList__Member__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TFC_SubsetList__Member__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_3 = {
	sizeof(struct TFC_SubsetList__Member__modeSpecificInfo),
	offsetof(struct TFC_SubsetList__Member__modeSpecificInfo, _asn_ctx),
	offsetof(struct TFC_SubsetList__Member__modeSpecificInfo, present),
	sizeof(((struct TFC_SubsetList__Member__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_3 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificInfo_constr_3, &asn_PER_type_modeSpecificInfo_constr_3, CHOICE_constraint },
	asn_MBR_modeSpecificInfo_3,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_Member_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TFC_SubsetList__Member, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TFC_SubsetList__Member, tfc_Subset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TFC_Subset,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tfc-Subset"
		},
};
static const ber_tlv_tag_t asn_DEF_Member_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Member_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* modeSpecificInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tfc-Subset */
};
static asn_SEQUENCE_specifics_t asn_SPC_Member_specs_2 = {
	sizeof(struct TFC_SubsetList__Member),
	offsetof(struct TFC_SubsetList__Member, _asn_ctx),
	asn_MAP_Member_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_Member_2 = {
	"SEQUENCE",
	"SEQUENCE",
	&asn_OP_SEQUENCE,
	asn_DEF_Member_tags_2,
	sizeof(asn_DEF_Member_tags_2)
		/sizeof(asn_DEF_Member_tags_2[0]), /* 1 */
	asn_DEF_Member_tags_2,	/* Same as above */
	sizeof(asn_DEF_Member_tags_2)
		/sizeof(asn_DEF_Member_tags_2[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Member_2,
	2,	/* Elements count */
	&asn_SPC_Member_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_TFC_SubsetList_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Member_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_TFC_SubsetList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_TFC_SubsetList_specs_1 = {
	sizeof(struct TFC_SubsetList),
	offsetof(struct TFC_SubsetList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_TFC_SubsetList = {
	"TFC-SubsetList",
	"TFC-SubsetList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_TFC_SubsetList_tags_1,
	sizeof(asn_DEF_TFC_SubsetList_tags_1)
		/sizeof(asn_DEF_TFC_SubsetList_tags_1[0]), /* 1 */
	asn_DEF_TFC_SubsetList_tags_1,	/* Same as above */
	sizeof(asn_DEF_TFC_SubsetList_tags_1)
		/sizeof(asn_DEF_TFC_SubsetList_tags_1[0]), /* 1 */
	{ &asn_OER_type_TFC_SubsetList_constr_1, &asn_PER_type_TFC_SubsetList_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_TFC_SubsetList_1,
	1,	/* Single element */
	&asn_SPC_TFC_SubsetList_specs_1	/* Additional specs */
};

