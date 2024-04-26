/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "QualityReportingQuantity.h"

#include "BLER-TransChIdList.h"
#include "SIR-TFCS-List.h"
static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_tdd_6[] = {
	{ ATF_POINTER, 1, offsetof(struct QualityReportingQuantity__modeSpecificInfo__tdd, sir_TFCS_List),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIR_TFCS_List,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sir-TFCS-List"
		},
};
static const int asn_MAP_tdd_oms_6[] = { 0 };
static const ber_tlv_tag_t asn_DEF_tdd_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* sir-TFCS-List */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_6 = {
	sizeof(struct QualityReportingQuantity__modeSpecificInfo__tdd),
	offsetof(struct QualityReportingQuantity__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_6,
	1,	/* Count of tags in the map */
	asn_MAP_tdd_oms_6,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_6 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_6,
	sizeof(asn_DEF_tdd_tags_6)
		/sizeof(asn_DEF_tdd_tags_6[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_6,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_6)
		/sizeof(asn_DEF_tdd_tags_6[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_6,
	1,	/* Elements count */
	&asn_SPC_tdd_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportingQuantity__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportingQuantity__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_4 = {
	sizeof(struct QualityReportingQuantity__modeSpecificInfo),
	offsetof(struct QualityReportingQuantity__modeSpecificInfo, _asn_ctx),
	offsetof(struct QualityReportingQuantity__modeSpecificInfo, present),
	sizeof(((struct QualityReportingQuantity__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_4 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificInfo_constr_4, &asn_PER_type_modeSpecificInfo_constr_4, CHOICE_constraint },
	asn_MBR_modeSpecificInfo_4,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_QualityReportingQuantity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportingQuantity, dl_TransChBLER),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-TransChBLER"
		},
	{ ATF_POINTER, 1, offsetof(struct QualityReportingQuantity, bler_dl_TransChIdList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BLER_TransChIdList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"bler-dl-TransChIdList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportingQuantity, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
};
static const int asn_MAP_QualityReportingQuantity_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_QualityReportingQuantity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_QualityReportingQuantity_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-TransChBLER */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* bler-dl-TransChIdList */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* modeSpecificInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_QualityReportingQuantity_specs_1 = {
	sizeof(struct QualityReportingQuantity),
	offsetof(struct QualityReportingQuantity, _asn_ctx),
	asn_MAP_QualityReportingQuantity_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_QualityReportingQuantity_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_QualityReportingQuantity = {
	"QualityReportingQuantity",
	"QualityReportingQuantity",
	&asn_OP_SEQUENCE,
	asn_DEF_QualityReportingQuantity_tags_1,
	sizeof(asn_DEF_QualityReportingQuantity_tags_1)
		/sizeof(asn_DEF_QualityReportingQuantity_tags_1[0]), /* 1 */
	asn_DEF_QualityReportingQuantity_tags_1,	/* Same as above */
	sizeof(asn_DEF_QualityReportingQuantity_tags_1)
		/sizeof(asn_DEF_QualityReportingQuantity_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_QualityReportingQuantity_1,
	3,	/* Elements count */
	&asn_SPC_QualityReportingQuantity_specs_1	/* Additional specs */
};
