/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UplinkPhysicalChannelControl-r5-IEs.h"

#include "CCTrCH-PowerControlInfo-r5.h"
#include "UL-TimingAdvanceControl-r4.h"
#include "OpenLoopPowerControl-IPDL-TDD-r4.h"
#include "HS-SICH-Power-Control-Info-TDD384.h"
#include "UL-SynchronisationParameters-r4.h"
static asn_oer_constraints_t asn_OER_type_tddOption_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_tddOption_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_tdd384_5[] = {
	{ ATF_POINTER, 6, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, timingAdvance),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_UL_TimingAdvanceControl_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timingAdvance"
		},
	{ ATF_POINTER, 5, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, alpha),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Alpha,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"alpha"
		},
	{ ATF_POINTER, 4, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, prach_ConstantValue),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ConstantValueTdd,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"prach-ConstantValue"
		},
	{ ATF_POINTER, 3, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, pusch_ConstantValue),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ConstantValueTdd,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pusch-ConstantValue"
		},
	{ ATF_POINTER, 2, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, openLoopPowerControl_IPDL_TDD),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OpenLoopPowerControl_IPDL_TDD_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"openLoopPowerControl-IPDL-TDD"
		},
	{ ATF_POINTER, 1, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, hs_SICH_PowerControl),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HS_SICH_Power_Control_Info_TDD384,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"hs-SICH-PowerControl"
		},
};
static const int asn_MAP_tdd384_oms_5[] = { 0, 1, 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_tdd384_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd384_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timingAdvance */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* alpha */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* prach-ConstantValue */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* pusch-ConstantValue */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* openLoopPowerControl-IPDL-TDD */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* hs-SICH-PowerControl */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd384_specs_5 = {
	sizeof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384),
	offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd384, _asn_ctx),
	asn_MAP_tdd384_tag2el_5,
	6,	/* Count of tags in the map */
	asn_MAP_tdd384_oms_5,	/* Optional members */
	6, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd384_5 = {
	"tdd384",
	"tdd384",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd384_tags_5,
	sizeof(asn_DEF_tdd384_tags_5)
		/sizeof(asn_DEF_tdd384_tags_5[0]) - 1, /* 1 */
	asn_DEF_tdd384_tags_5,	/* Same as above */
	sizeof(asn_DEF_tdd384_tags_5)
		/sizeof(asn_DEF_tdd384_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd384_5,
	6,	/* Elements count */
	&asn_SPC_tdd384_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd128_12[] = {
	{ ATF_POINTER, 1, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd128, ul_SynchronisationParameters),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_SynchronisationParameters_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-SynchronisationParameters"
		},
};
static const int asn_MAP_tdd128_oms_12[] = { 0 };
static const ber_tlv_tag_t asn_DEF_tdd128_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd128_tag2el_12[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* ul-SynchronisationParameters */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd128_specs_12 = {
	sizeof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd128),
	offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption__tdd128, _asn_ctx),
	asn_MAP_tdd128_tag2el_12,
	1,	/* Count of tags in the map */
	asn_MAP_tdd128_oms_12,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_12 = {
	"tdd128",
	"tdd128",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd128_tags_12,
	sizeof(asn_DEF_tdd128_tags_12)
		/sizeof(asn_DEF_tdd128_tags_12[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_12,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_12)
		/sizeof(asn_DEF_tdd128_tags_12[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd128_12,
	1,	/* Elements count */
	&asn_SPC_tdd128_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tddOption_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_tdd384_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd128_12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd128"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_tddOption_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tdd384 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd128 */
};
static asn_CHOICE_specifics_t asn_SPC_tddOption_specs_4 = {
	sizeof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption),
	offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption, _asn_ctx),
	offsetof(struct UplinkPhysicalChannelControl_r5_IEs__tddOption, present),
	sizeof(((struct UplinkPhysicalChannelControl_r5_IEs__tddOption *)0)->present),
	asn_MAP_tddOption_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tddOption_4 = {
	"tddOption",
	"tddOption",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_tddOption_constr_4, &asn_PER_type_tddOption_constr_4, CHOICE_constraint },
	asn_MBR_tddOption_4,
	2,	/* Elements count */
	&asn_SPC_tddOption_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_UplinkPhysicalChannelControl_r5_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct UplinkPhysicalChannelControl_r5_IEs, ccTrCH_PowerControlInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CCTrCH_PowerControlInfo_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ccTrCH-PowerControlInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct UplinkPhysicalChannelControl_r5_IEs, specialBurstScheduling),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SpecialBurstScheduling,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"specialBurstScheduling"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UplinkPhysicalChannelControl_r5_IEs, tddOption),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tddOption_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tddOption"
		},
};
static const int asn_MAP_UplinkPhysicalChannelControl_r5_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UplinkPhysicalChannelControl_r5_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ccTrCH-PowerControlInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* specialBurstScheduling */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* tddOption */
};
asn_SEQUENCE_specifics_t asn_SPC_UplinkPhysicalChannelControl_r5_IEs_specs_1 = {
	sizeof(struct UplinkPhysicalChannelControl_r5_IEs),
	offsetof(struct UplinkPhysicalChannelControl_r5_IEs, _asn_ctx),
	asn_MAP_UplinkPhysicalChannelControl_r5_IEs_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_UplinkPhysicalChannelControl_r5_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UplinkPhysicalChannelControl_r5_IEs = {
	"UplinkPhysicalChannelControl-r5-IEs",
	"UplinkPhysicalChannelControl-r5-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1,
	sizeof(asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1)
		/sizeof(asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1[0]), /* 1 */
	asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1)
		/sizeof(asn_DEF_UplinkPhysicalChannelControl_r5_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UplinkPhysicalChannelControl_r5_IEs_1,
	3,	/* Elements count */
	&asn_SPC_UplinkPhysicalChannelControl_r5_IEs_specs_1	/* Additional specs */
};

