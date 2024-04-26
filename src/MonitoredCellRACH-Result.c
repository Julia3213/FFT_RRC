/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MonitoredCellRACH-Result.h"

#include "SFN-SFN-ObsTimeDifference.h"
static asn_oer_constraints_t asn_OER_type_measurementQuantity_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_measurementQuantity_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_measurementQuantity_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity, choice.cpich_Ec_N0),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CPICH_Ec_N0,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cpich-Ec-N0"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity, choice.cpich_RSCP),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CPICH_RSCP,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cpich-RSCP"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity, choice.pathloss),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Pathloss,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pathloss"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity, choice.spare),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_measurementQuantity_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cpich-Ec-N0 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cpich-RSCP */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* pathloss */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* spare */
};
static asn_CHOICE_specifics_t asn_SPC_measurementQuantity_specs_6 = {
	sizeof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity),
	offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity, _asn_ctx),
	offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity, present),
	sizeof(((struct MonitoredCellRACH_Result__modeSpecificInfo__fdd__measurementQuantity *)0)->present),
	asn_MAP_measurementQuantity_tag2el_6,
	4,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_measurementQuantity_6 = {
	"measurementQuantity",
	"measurementQuantity",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_measurementQuantity_constr_6, &asn_PER_type_measurementQuantity_constr_6, CHOICE_constraint },
	asn_MBR_measurementQuantity_6,
	4,	/* Elements count */
	&asn_SPC_measurementQuantity_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCPICH-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd, measurementQuantity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_measurementQuantity_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measurementQuantity"
		},
};
static const int asn_MAP_fdd_oms_4[] = { 1 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* measurementQuantity */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_4 = {
	sizeof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd),
	offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_4,
	2,	/* Count of tags in the map */
	asn_MAP_fdd_oms_4,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_4 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_4,
	sizeof(asn_DEF_fdd_tags_4)
		/sizeof(asn_DEF_fdd_tags_4[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_4,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_4)
		/sizeof(asn_DEF_fdd_tags_4[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_4,
	2,	/* Elements count */
	&asn_SPC_fdd_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_11[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__tdd, cellParametersID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellParametersID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellParametersID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__tdd, primaryCCPCH_RSCP),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCCPCH_RSCP,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCCPCH-RSCP"
		},
};
static const ber_tlv_tag_t asn_DEF_tdd_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellParametersID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* primaryCCPCH-RSCP */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_11 = {
	sizeof(struct MonitoredCellRACH_Result__modeSpecificInfo__tdd),
	offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_11,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_11 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_11,
	sizeof(asn_DEF_tdd_tags_11)
		/sizeof(asn_DEF_tdd_tags_11[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_11,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_11)
		/sizeof(asn_DEF_tdd_tags_11[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_11,
	2,	/* Elements count */
	&asn_SPC_tdd_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_11,
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
	sizeof(struct MonitoredCellRACH_Result__modeSpecificInfo),
	offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo, _asn_ctx),
	offsetof(struct MonitoredCellRACH_Result__modeSpecificInfo, present),
	sizeof(((struct MonitoredCellRACH_Result__modeSpecificInfo *)0)->present),
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

asn_TYPE_member_t asn_MBR_MonitoredCellRACH_Result_1[] = {
	{ ATF_POINTER, 1, offsetof(struct MonitoredCellRACH_Result, sfn_SFN_ObsTimeDifference),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SFN_SFN_ObsTimeDifference,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sfn-SFN-ObsTimeDifference"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MonitoredCellRACH_Result, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
};
static const int asn_MAP_MonitoredCellRACH_Result_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_MonitoredCellRACH_Result_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MonitoredCellRACH_Result_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sfn-SFN-ObsTimeDifference */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* modeSpecificInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_MonitoredCellRACH_Result_specs_1 = {
	sizeof(struct MonitoredCellRACH_Result),
	offsetof(struct MonitoredCellRACH_Result, _asn_ctx),
	asn_MAP_MonitoredCellRACH_Result_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_MonitoredCellRACH_Result_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MonitoredCellRACH_Result = {
	"MonitoredCellRACH-Result",
	"MonitoredCellRACH-Result",
	&asn_OP_SEQUENCE,
	asn_DEF_MonitoredCellRACH_Result_tags_1,
	sizeof(asn_DEF_MonitoredCellRACH_Result_tags_1)
		/sizeof(asn_DEF_MonitoredCellRACH_Result_tags_1[0]), /* 1 */
	asn_DEF_MonitoredCellRACH_Result_tags_1,	/* Same as above */
	sizeof(asn_DEF_MonitoredCellRACH_Result_tags_1)
		/sizeof(asn_DEF_MonitoredCellRACH_Result_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MonitoredCellRACH_Result_1,
	2,	/* Elements count */
	&asn_SPC_MonitoredCellRACH_Result_specs_1	/* Additional specs */
};
