/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TransportChannelReconfiguration-r5-IEs.h"

#include "IntegrityProtectionModeInfo.h"
#include "CipheringModeInfo.h"
#include "U-RNTI.h"
#include "CN-InformationInfo.h"
#include "DL-CounterSynchronisationInfo-r5.h"
#include "UL-CommonTransChInfo-r4.h"
#include "UL-AddReconfTransChInfoList.h"
#include "DL-CommonTransChInfo-r4.h"
#include "DL-AddReconfTransChInfoList-r5.h"
#include "FrequencyInfo.h"
#include "UL-ChannelRequirement-r5.h"
#include "DL-HSPDSCH-Information.h"
#include "DL-CommonInformation-r5.h"
#include "DL-InformationPerRL-List-r5.h"
#include "DRAC-StaticInformationList.h"
#include "DL-PDSCH-Information.h"
static asn_oer_constraints_t asn_OER_type_dummy_constr_16 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_dummy_constr_16 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_modeSpecificPhysChInfo_constr_26 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificPhysChInfo_constr_26 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_17[] = {
	{ ATF_POINTER, 2, offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy__fdd, dummy1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CPCH_SetID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy1"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy__fdd, dummy2),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DRAC_StaticInformationList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy2"
		},
};
static const int asn_MAP_fdd_oms_17[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dummy1 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dummy2 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_17 = {
	sizeof(struct TransportChannelReconfiguration_r5_IEs__dummy__fdd),
	offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_17,
	2,	/* Count of tags in the map */
	asn_MAP_fdd_oms_17,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_17 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_17,
	sizeof(asn_DEF_fdd_tags_17)
		/sizeof(asn_DEF_fdd_tags_17[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_17,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_17)
		/sizeof(asn_DEF_fdd_tags_17[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_17,
	2,	/* Elements count */
	&asn_SPC_fdd_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_dummy_16[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_dummy_tag2el_16[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_dummy_specs_16 = {
	sizeof(struct TransportChannelReconfiguration_r5_IEs__dummy),
	offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy, _asn_ctx),
	offsetof(struct TransportChannelReconfiguration_r5_IEs__dummy, present),
	sizeof(((struct TransportChannelReconfiguration_r5_IEs__dummy *)0)->present),
	asn_MAP_dummy_tag2el_16,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dummy_16 = {
	"dummy",
	"dummy",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_dummy_constr_16, &asn_PER_type_dummy_constr_16, CHOICE_constraint },
	asn_MBR_dummy_16,
	2,	/* Elements count */
	&asn_SPC_dummy_specs_16	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_27[] = {
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo__fdd, dummy),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_PDSCH_Information,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
};
static const int asn_MAP_fdd_oms_27[] = { 0 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_27[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_27[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* dummy */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_27 = {
	sizeof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo__fdd),
	offsetof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_27,
	1,	/* Count of tags in the map */
	asn_MAP_fdd_oms_27,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_27 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_27,
	sizeof(asn_DEF_fdd_tags_27)
		/sizeof(asn_DEF_fdd_tags_27[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_27,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_27)
		/sizeof(asn_DEF_fdd_tags_27[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_27,
	1,	/* Elements count */
	&asn_SPC_fdd_specs_27	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificPhysChInfo_26[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_27,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificPhysChInfo_tag2el_26[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificPhysChInfo_specs_26 = {
	sizeof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo),
	offsetof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo, _asn_ctx),
	offsetof(struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo, present),
	sizeof(((struct TransportChannelReconfiguration_r5_IEs__modeSpecificPhysChInfo *)0)->present),
	asn_MAP_modeSpecificPhysChInfo_tag2el_26,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificPhysChInfo_26 = {
	"modeSpecificPhysChInfo",
	"modeSpecificPhysChInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificPhysChInfo_constr_26, &asn_PER_type_modeSpecificPhysChInfo_constr_26, CHOICE_constraint },
	asn_MBR_modeSpecificPhysChInfo_26,
	2,	/* Elements count */
	&asn_SPC_modeSpecificPhysChInfo_specs_26	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_TransportChannelReconfiguration_r5_IEs_1[] = {
	{ ATF_POINTER, 7, offsetof(struct TransportChannelReconfiguration_r5_IEs, integrityProtectionModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtectionModeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"integrityProtectionModeInfo"
		},
	{ ATF_POINTER, 6, offsetof(struct TransportChannelReconfiguration_r5_IEs, cipheringModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CipheringModeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cipheringModeInfo"
		},
	{ ATF_POINTER, 5, offsetof(struct TransportChannelReconfiguration_r5_IEs, activationTime),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"activationTime"
		},
	{ ATF_POINTER, 4, offsetof(struct TransportChannelReconfiguration_r5_IEs, new_U_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_U_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-U-RNTI"
		},
	{ ATF_POINTER, 3, offsetof(struct TransportChannelReconfiguration_r5_IEs, new_C_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_C_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-C-RNTI"
		},
	{ ATF_POINTER, 2, offsetof(struct TransportChannelReconfiguration_r5_IEs, new_DSCH_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DSCH_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-DSCH-RNTI"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfiguration_r5_IEs, new_H_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_H_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-H-RNTI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfiguration_r5_IEs, rrc_StateIndicator),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_StateIndicator,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-StateIndicator"
		},
	{ ATF_POINTER, 12, offsetof(struct TransportChannelReconfiguration_r5_IEs, utran_DRX_CycleLengthCoeff),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_DRX_CycleLengthCoefficient,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"utran-DRX-CycleLengthCoeff"
		},
	{ ATF_POINTER, 11, offsetof(struct TransportChannelReconfiguration_r5_IEs, cn_InformationInfo),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CN_InformationInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cn-InformationInfo"
		},
	{ ATF_POINTER, 10, offsetof(struct TransportChannelReconfiguration_r5_IEs, ura_Identity),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_URA_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ura-Identity"
		},
	{ ATF_POINTER, 9, offsetof(struct TransportChannelReconfiguration_r5_IEs, dl_CounterSynchronisationInfo),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CounterSynchronisationInfo_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CounterSynchronisationInfo"
		},
	{ ATF_POINTER, 8, offsetof(struct TransportChannelReconfiguration_r5_IEs, ul_CommonTransChInfo),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_CommonTransChInfo_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-CommonTransChInfo"
		},
	{ ATF_POINTER, 7, offsetof(struct TransportChannelReconfiguration_r5_IEs, ul_AddReconfTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_AddReconfTransChInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-AddReconfTransChInfoList"
		},
	{ ATF_POINTER, 6, offsetof(struct TransportChannelReconfiguration_r5_IEs, dummy),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_dummy_16,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
	{ ATF_POINTER, 5, offsetof(struct TransportChannelReconfiguration_r5_IEs, dl_CommonTransChInfo),
		(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CommonTransChInfo_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CommonTransChInfo"
		},
	{ ATF_POINTER, 4, offsetof(struct TransportChannelReconfiguration_r5_IEs, dl_AddReconfTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (16 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_AddReconfTransChInfoList_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-AddReconfTransChInfoList"
		},
	{ ATF_POINTER, 3, offsetof(struct TransportChannelReconfiguration_r5_IEs, frequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (17 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"frequencyInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct TransportChannelReconfiguration_r5_IEs, maxAllowedUL_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (18 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxAllowedUL_TX_Power,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxAllowedUL-TX-Power"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfiguration_r5_IEs, ul_ChannelRequirement),
		(ASN_TAG_CLASS_CONTEXT | (19 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_UL_ChannelRequirement_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-ChannelRequirement"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfiguration_r5_IEs, modeSpecificPhysChInfo),
		(ASN_TAG_CLASS_CONTEXT | (20 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificPhysChInfo_26,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificPhysChInfo"
		},
	{ ATF_POINTER, 3, offsetof(struct TransportChannelReconfiguration_r5_IEs, dl_HSPDSCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (21 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_HSPDSCH_Information,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-HSPDSCH-Information"
		},
	{ ATF_POINTER, 2, offsetof(struct TransportChannelReconfiguration_r5_IEs, dl_CommonInformation),
		(ASN_TAG_CLASS_CONTEXT | (22 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CommonInformation_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CommonInformation"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfiguration_r5_IEs, dl_InformationPerRL_List),
		(ASN_TAG_CLASS_CONTEXT | (23 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_InformationPerRL_List_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-InformationPerRL-List"
		},
};
static const int asn_MAP_TransportChannelReconfiguration_r5_IEs_oms_1[] = { 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23 };
static const ber_tlv_tag_t asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TransportChannelReconfiguration_r5_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* integrityProtectionModeInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cipheringModeInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* activationTime */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* new-U-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* new-C-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* new-DSCH-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* new-H-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* rrc-StateIndicator */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* utran-DRX-CycleLengthCoeff */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* cn-InformationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* ura-Identity */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* dl-CounterSynchronisationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* ul-CommonTransChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* ul-AddReconfTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 14, 0, 0 }, /* dummy */
    { (ASN_TAG_CLASS_CONTEXT | (15 << 2)), 15, 0, 0 }, /* dl-CommonTransChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (16 << 2)), 16, 0, 0 }, /* dl-AddReconfTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (17 << 2)), 17, 0, 0 }, /* frequencyInfo */
    { (ASN_TAG_CLASS_CONTEXT | (18 << 2)), 18, 0, 0 }, /* maxAllowedUL-TX-Power */
    { (ASN_TAG_CLASS_CONTEXT | (19 << 2)), 19, 0, 0 }, /* ul-ChannelRequirement */
    { (ASN_TAG_CLASS_CONTEXT | (20 << 2)), 20, 0, 0 }, /* modeSpecificPhysChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (21 << 2)), 21, 0, 0 }, /* dl-HSPDSCH-Information */
    { (ASN_TAG_CLASS_CONTEXT | (22 << 2)), 22, 0, 0 }, /* dl-CommonInformation */
    { (ASN_TAG_CLASS_CONTEXT | (23 << 2)), 23, 0, 0 } /* dl-InformationPerRL-List */
};
asn_SEQUENCE_specifics_t asn_SPC_TransportChannelReconfiguration_r5_IEs_specs_1 = {
	sizeof(struct TransportChannelReconfiguration_r5_IEs),
	offsetof(struct TransportChannelReconfiguration_r5_IEs, _asn_ctx),
	asn_MAP_TransportChannelReconfiguration_r5_IEs_tag2el_1,
	24,	/* Count of tags in the map */
	asn_MAP_TransportChannelReconfiguration_r5_IEs_oms_1,	/* Optional members */
	22, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_TransportChannelReconfiguration_r5_IEs = {
	"TransportChannelReconfiguration-r5-IEs",
	"TransportChannelReconfiguration-r5-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1,
	sizeof(asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1)
		/sizeof(asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1[0]), /* 1 */
	asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1)
		/sizeof(asn_DEF_TransportChannelReconfiguration_r5_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_TransportChannelReconfiguration_r5_IEs_1,
	24,	/* Elements count */
	&asn_SPC_TransportChannelReconfiguration_r5_IEs_specs_1	/* Additional specs */
};
