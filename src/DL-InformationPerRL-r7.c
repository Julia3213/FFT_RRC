/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-InformationPerRL-r7.h"

#include "E-AGCH-Information.h"
static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_dl_dpchInfo_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_dl_dpchInfo_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_e_HICH_Info_constr_12 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_e_HICH_Info_constr_12 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_e_RGCH_Info_constr_15 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_e_RGCH_Info_constr_15 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo__fdd, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCPICH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo__fdd, servingHSDSCH_RL_indicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"servingHSDSCH-RL-indicator"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo__fdd, servingEDCH_RL_indicator),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"servingEDCH-RL-indicator"
		},
};
static const ber_tlv_tag_t asn_DEF_fdd_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* servingHSDSCH-RL-indicator */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* servingEDCH-RL-indicator */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_3 = {
	sizeof(struct DL_InformationPerRL_r7__modeSpecificInfo__fdd),
	offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo__fdd, _asn_ctx),
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

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PrimaryCCPCH_Info_r7,
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
	sizeof(struct DL_InformationPerRL_r7__modeSpecificInfo),
	offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo, _asn_ctx),
	offsetof(struct DL_InformationPerRL_r7__modeSpecificInfo, present),
	sizeof(((struct DL_InformationPerRL_r7__modeSpecificInfo *)0)->present),
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

static asn_TYPE_member_t asn_MBR_dl_dpchInfo_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__dl_dpchInfo, choice.dl_DPCH_InfoPerRL),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_DL_DPCH_InfoPerRL_r7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-DPCH-InfoPerRL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__dl_dpchInfo, choice.dl_FDPCH_InfoPerRL),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_FDPCH_InfoPerRL_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-FDPCH-InfoPerRL"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_dl_dpchInfo_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-DPCH-InfoPerRL */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-FDPCH-InfoPerRL */
};
static asn_CHOICE_specifics_t asn_SPC_dl_dpchInfo_specs_8 = {
	sizeof(struct DL_InformationPerRL_r7__dl_dpchInfo),
	offsetof(struct DL_InformationPerRL_r7__dl_dpchInfo, _asn_ctx),
	offsetof(struct DL_InformationPerRL_r7__dl_dpchInfo, present),
	sizeof(((struct DL_InformationPerRL_r7__dl_dpchInfo *)0)->present),
	asn_MAP_dl_dpchInfo_tag2el_8,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dl_dpchInfo_8 = {
	"dl-dpchInfo",
	"dl-dpchInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_dl_dpchInfo_constr_8, &asn_PER_type_dl_dpchInfo_constr_8, CHOICE_constraint },
	asn_MBR_dl_dpchInfo_8,
	2,	/* Elements count */
	&asn_SPC_dl_dpchInfo_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_e_HICH_Info_12[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__e_HICH_Info, choice.e_HICH_Information),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_HICH_Information,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-HICH-Information"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__e_HICH_Info, choice.releaseIndicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"releaseIndicator"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_e_HICH_Info_tag2el_12[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-HICH-Information */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* releaseIndicator */
};
static asn_CHOICE_specifics_t asn_SPC_e_HICH_Info_specs_12 = {
	sizeof(struct DL_InformationPerRL_r7__e_HICH_Info),
	offsetof(struct DL_InformationPerRL_r7__e_HICH_Info, _asn_ctx),
	offsetof(struct DL_InformationPerRL_r7__e_HICH_Info, present),
	sizeof(((struct DL_InformationPerRL_r7__e_HICH_Info *)0)->present),
	asn_MAP_e_HICH_Info_tag2el_12,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_e_HICH_Info_12 = {
	"e-HICH-Info",
	"e-HICH-Info",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_e_HICH_Info_constr_12, &asn_PER_type_e_HICH_Info_constr_12, CHOICE_constraint },
	asn_MBR_e_HICH_Info_12,
	2,	/* Elements count */
	&asn_SPC_e_HICH_Info_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_e_RGCH_Info_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__e_RGCH_Info, choice.e_RGCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RGCH_Information,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-RGCH-Information"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7__e_RGCH_Info, choice.releaseIndicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"releaseIndicator"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_e_RGCH_Info_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-RGCH-Information */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* releaseIndicator */
};
static asn_CHOICE_specifics_t asn_SPC_e_RGCH_Info_specs_15 = {
	sizeof(struct DL_InformationPerRL_r7__e_RGCH_Info),
	offsetof(struct DL_InformationPerRL_r7__e_RGCH_Info, _asn_ctx),
	offsetof(struct DL_InformationPerRL_r7__e_RGCH_Info, present),
	sizeof(((struct DL_InformationPerRL_r7__e_RGCH_Info *)0)->present),
	asn_MAP_e_RGCH_Info_tag2el_15,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_e_RGCH_Info_15 = {
	"e-RGCH-Info",
	"e-RGCH-Info",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_e_RGCH_Info_constr_15, &asn_PER_type_e_RGCH_Info_constr_15, CHOICE_constraint },
	asn_MBR_e_RGCH_Info_15,
	2,	/* Elements count */
	&asn_SPC_e_RGCH_Info_specs_15	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DL_InformationPerRL_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_r7, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
	{ ATF_POINTER, 5, offsetof(struct DL_InformationPerRL_r7, dl_dpchInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_dl_dpchInfo_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-dpchInfo"
		},
	{ ATF_POINTER, 4, offsetof(struct DL_InformationPerRL_r7, e_AGCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_AGCH_Information,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-AGCH-Information"
		},
	{ ATF_POINTER, 3, offsetof(struct DL_InformationPerRL_r7, e_HICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_e_HICH_Info_12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-HICH-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct DL_InformationPerRL_r7, e_RGCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_e_RGCH_Info_15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-RGCH-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_InformationPerRL_r7, cell_id),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cell-id"
		},
};
static const int asn_MAP_DL_InformationPerRL_r7_oms_1[] = { 1, 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_DL_InformationPerRL_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_InformationPerRL_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* modeSpecificInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-dpchInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* e-AGCH-Information */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* e-HICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* e-RGCH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* cell-id */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_InformationPerRL_r7_specs_1 = {
	sizeof(struct DL_InformationPerRL_r7),
	offsetof(struct DL_InformationPerRL_r7, _asn_ctx),
	asn_MAP_DL_InformationPerRL_r7_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_DL_InformationPerRL_r7_oms_1,	/* Optional members */
	5, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_InformationPerRL_r7 = {
	"DL-InformationPerRL-r7",
	"DL-InformationPerRL-r7",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_InformationPerRL_r7_tags_1,
	sizeof(asn_DEF_DL_InformationPerRL_r7_tags_1)
		/sizeof(asn_DEF_DL_InformationPerRL_r7_tags_1[0]), /* 1 */
	asn_DEF_DL_InformationPerRL_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_InformationPerRL_r7_tags_1)
		/sizeof(asn_DEF_DL_InformationPerRL_r7_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_InformationPerRL_r7_1,
	6,	/* Elements count */
	&asn_SPC_DL_InformationPerRL_r7_specs_1	/* Additional specs */
};

