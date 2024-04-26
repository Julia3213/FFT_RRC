/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-CommonInformation-r7.h"

#include "DPCH-CompressedModeInfo.h"
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_dl_dpchInfoCommon_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_dl_dpchInfoCommon_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_tddOption_constr_11 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_tddOption_constr_11 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_mac_hsResetIndicator_constr_17 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_mac_hsResetIndicator_constr_17 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_postVerificationPeriod_constr_19 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_postVerificationPeriod_constr_19 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_dl_dpchInfoCommon_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__dl_dpchInfoCommon, choice.dl_DPCH_InfoCommon),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_DPCH_InfoCommon_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-DPCH-InfoCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__dl_dpchInfoCommon, choice.dl_FDPCH_InfoCommon),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_FDPCH_InfoCommon_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-FDPCH-InfoCommon"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_dl_dpchInfoCommon_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-DPCH-InfoCommon */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-FDPCH-InfoCommon */
};
static asn_CHOICE_specifics_t asn_SPC_dl_dpchInfoCommon_specs_2 = {
	sizeof(struct DL_CommonInformation_r7__dl_dpchInfoCommon),
	offsetof(struct DL_CommonInformation_r7__dl_dpchInfoCommon, _asn_ctx),
	offsetof(struct DL_CommonInformation_r7__dl_dpchInfoCommon, present),
	sizeof(((struct DL_CommonInformation_r7__dl_dpchInfoCommon *)0)->present),
	asn_MAP_dl_dpchInfoCommon_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dl_dpchInfoCommon_2 = {
	"dl-dpchInfoCommon",
	"dl-dpchInfoCommon",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_dl_dpchInfoCommon_constr_2, &asn_PER_type_dl_dpchInfoCommon_constr_2, CHOICE_constraint },
	asn_MBR_dl_dpchInfoCommon_2,
	2,	/* Elements count */
	&asn_SPC_dl_dpchInfoCommon_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_6[] = {
	{ ATF_POINTER, 3, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__fdd, defaultDPCH_OffsetValue),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DefaultDPCH_OffsetValueFDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"defaultDPCH-OffsetValue"
		},
	{ ATF_POINTER, 2, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__fdd, dpch_CompressedModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DPCH_CompressedModeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dpch-CompressedModeInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__fdd, tx_DiversityMode),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TX_DiversityMode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tx-DiversityMode"
		},
};
static const int asn_MAP_fdd_oms_6[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* defaultDPCH-OffsetValue */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dpch-CompressedModeInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* tx-DiversityMode */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_6 = {
	sizeof(struct DL_CommonInformation_r7__modeSpecificInfo__fdd),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_6,
	3,	/* Count of tags in the map */
	asn_MAP_fdd_oms_6,	/* Optional members */
	3, 0,	/* Root/Additions */
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
	3,	/* Elements count */
	&asn_SPC_fdd_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd128_14[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption__tdd128, tstd_Indicator),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tstd-Indicator"
		},
};
static const ber_tlv_tag_t asn_DEF_tdd128_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd128_tag2el_14[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* tstd-Indicator */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd128_specs_14 = {
	sizeof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption__tdd128),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption__tdd128, _asn_ctx),
	asn_MAP_tdd128_tag2el_14,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_14 = {
	"tdd128",
	"tdd128",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd128_tags_14,
	sizeof(asn_DEF_tdd128_tags_14)
		/sizeof(asn_DEF_tdd128_tags_14[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_14,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_14)
		/sizeof(asn_DEF_tdd128_tags_14[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd128_14,
	1,	/* Elements count */
	&asn_SPC_tdd128_specs_14	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tddOption_11[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption, choice.tdd768),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd768"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_tdd128_14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd128"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_tddOption_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tdd384 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tdd768 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* tdd128 */
};
static asn_CHOICE_specifics_t asn_SPC_tddOption_specs_11 = {
	sizeof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption, _asn_ctx),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption, present),
	sizeof(((struct DL_CommonInformation_r7__modeSpecificInfo__tdd__tddOption *)0)->present),
	asn_MAP_tddOption_tag2el_11,
	3,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tddOption_11 = {
	"tddOption",
	"tddOption",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_tddOption_constr_11, &asn_PER_type_tddOption_constr_11, CHOICE_constraint },
	asn_MBR_tddOption_11,
	3,	/* Elements count */
	&asn_SPC_tddOption_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_10[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd, tddOption),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tddOption_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tddOption"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd, defaultDPCH_OffsetValue),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DefaultDPCH_OffsetValueTDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"defaultDPCH-OffsetValue"
		},
};
static const int asn_MAP_tdd_oms_10[] = { 1 };
static const ber_tlv_tag_t asn_DEF_tdd_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tddOption */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* defaultDPCH-OffsetValue */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_10 = {
	sizeof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_10,
	2,	/* Count of tags in the map */
	asn_MAP_tdd_oms_10,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_10 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_10,
	sizeof(asn_DEF_tdd_tags_10)
		/sizeof(asn_DEF_tdd_tags_10[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_10,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_10)
		/sizeof(asn_DEF_tdd_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_10,
	2,	/* Elements count */
	&asn_SPC_tdd_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_10,
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
	sizeof(struct DL_CommonInformation_r7__modeSpecificInfo),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo, _asn_ctx),
	offsetof(struct DL_CommonInformation_r7__modeSpecificInfo, present),
	sizeof(((struct DL_CommonInformation_r7__modeSpecificInfo *)0)->present),
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

static const asn_INTEGER_enum_map_t asn_MAP_mac_hsResetIndicator_value2enum_17[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_mac_hsResetIndicator_enum2value_17[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_mac_hsResetIndicator_specs_17 = {
	asn_MAP_mac_hsResetIndicator_value2enum_17,	/* "tag" => N; sorted by tag */
	asn_MAP_mac_hsResetIndicator_enum2value_17,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_mac_hsResetIndicator_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_mac_hsResetIndicator_17 = {
	"mac-hsResetIndicator",
	"mac-hsResetIndicator",
	&asn_OP_NativeEnumerated,
	asn_DEF_mac_hsResetIndicator_tags_17,
	sizeof(asn_DEF_mac_hsResetIndicator_tags_17)
		/sizeof(asn_DEF_mac_hsResetIndicator_tags_17[0]) - 1, /* 1 */
	asn_DEF_mac_hsResetIndicator_tags_17,	/* Same as above */
	sizeof(asn_DEF_mac_hsResetIndicator_tags_17)
		/sizeof(asn_DEF_mac_hsResetIndicator_tags_17[0]), /* 2 */
	{ &asn_OER_type_mac_hsResetIndicator_constr_17, &asn_PER_type_mac_hsResetIndicator_constr_17, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_mac_hsResetIndicator_specs_17	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_postVerificationPeriod_value2enum_19[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_postVerificationPeriod_enum2value_19[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_postVerificationPeriod_specs_19 = {
	asn_MAP_postVerificationPeriod_value2enum_19,	/* "tag" => N; sorted by tag */
	asn_MAP_postVerificationPeriod_enum2value_19,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_postVerificationPeriod_tags_19[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_postVerificationPeriod_19 = {
	"postVerificationPeriod",
	"postVerificationPeriod",
	&asn_OP_NativeEnumerated,
	asn_DEF_postVerificationPeriod_tags_19,
	sizeof(asn_DEF_postVerificationPeriod_tags_19)
		/sizeof(asn_DEF_postVerificationPeriod_tags_19[0]) - 1, /* 1 */
	asn_DEF_postVerificationPeriod_tags_19,	/* Same as above */
	sizeof(asn_DEF_postVerificationPeriod_tags_19)
		/sizeof(asn_DEF_postVerificationPeriod_tags_19[0]), /* 2 */
	{ &asn_OER_type_postVerificationPeriod_constr_19, &asn_PER_type_postVerificationPeriod_constr_19, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_postVerificationPeriod_specs_19	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DL_CommonInformation_r7_1[] = {
	{ ATF_POINTER, 1, offsetof(struct DL_CommonInformation_r7, dl_dpchInfoCommon),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_dl_dpchInfoCommon_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-dpchInfoCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_CommonInformation_r7, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct DL_CommonInformation_r7, mac_hsResetIndicator),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_mac_hsResetIndicator_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mac-hsResetIndicator"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_CommonInformation_r7, postVerificationPeriod),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_postVerificationPeriod_19,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"postVerificationPeriod"
		},
};
static const int asn_MAP_DL_CommonInformation_r7_oms_1[] = { 0, 2, 3 };
static const ber_tlv_tag_t asn_DEF_DL_CommonInformation_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_CommonInformation_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-dpchInfoCommon */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* modeSpecificInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* mac-hsResetIndicator */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* postVerificationPeriod */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_CommonInformation_r7_specs_1 = {
	sizeof(struct DL_CommonInformation_r7),
	offsetof(struct DL_CommonInformation_r7, _asn_ctx),
	asn_MAP_DL_CommonInformation_r7_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_DL_CommonInformation_r7_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_CommonInformation_r7 = {
	"DL-CommonInformation-r7",
	"DL-CommonInformation-r7",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_CommonInformation_r7_tags_1,
	sizeof(asn_DEF_DL_CommonInformation_r7_tags_1)
		/sizeof(asn_DEF_DL_CommonInformation_r7_tags_1[0]), /* 1 */
	asn_DEF_DL_CommonInformation_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_CommonInformation_r7_tags_1)
		/sizeof(asn_DEF_DL_CommonInformation_r7_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_CommonInformation_r7_1,
	4,	/* Elements count */
	&asn_SPC_DL_CommonInformation_r7_specs_1	/* Additional specs */
};
