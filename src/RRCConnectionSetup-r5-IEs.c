/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RRCConnectionSetup-r5-IEs.h"

#include "CapabilityUpdateRequirement-r5.h"
#include "FrequencyInfo.h"
#include "UL-ChannelRequirement-r4.h"
#include "DL-CommonInformation-r4.h"
#include "DL-InformationPerRL-List-r5bis.h"
#include "UL-CommonTransChInfo-r4.h"
#include "UL-AddReconfTransChInfoList.h"
#include "DL-CommonTransChInfo-r4.h"
#include "DL-AddReconfTransChInfoList-r4.h"
static asn_oer_constraints_t asn_OER_type_preConfigMode_constr_16 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_preConfigMode_constr_16 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_specificationMode_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_specificationMode_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_complete_9[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete, srb_InformationSetupList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SRB_InformationSetupList2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"srb-InformationSetupList"
		},
	{ ATF_POINTER, 4, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete, ul_CommonTransChInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_CommonTransChInfo_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-CommonTransChInfo"
		},
	{ ATF_POINTER, 3, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete, ul_AddReconfTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_AddReconfTransChInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-AddReconfTransChInfoList"
		},
	{ ATF_POINTER, 2, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete, dl_CommonTransChInfo),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CommonTransChInfo_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CommonTransChInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete, dl_AddReconfTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_AddReconfTransChInfoList_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-AddReconfTransChInfoList"
		},
};
static const int asn_MAP_complete_oms_9[] = { 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_complete_tags_9[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_complete_tag2el_9[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* srb-InformationSetupList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ul-CommonTransChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* ul-AddReconfTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* dl-CommonTransChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* dl-AddReconfTransChInfoList */
};
static asn_SEQUENCE_specifics_t asn_SPC_complete_specs_9 = {
	sizeof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__complete, _asn_ctx),
	asn_MAP_complete_tag2el_9,
	5,	/* Count of tags in the map */
	asn_MAP_complete_oms_9,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_complete_9 = {
	"complete",
	"complete",
	&asn_OP_SEQUENCE,
	asn_DEF_complete_tags_9,
	sizeof(asn_DEF_complete_tags_9)
		/sizeof(asn_DEF_complete_tags_9[0]) - 1, /* 1 */
	asn_DEF_complete_tags_9,	/* Same as above */
	sizeof(asn_DEF_complete_tags_9)
		/sizeof(asn_DEF_complete_tags_9[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_complete_9,
	5,	/* Elements count */
	&asn_SPC_complete_specs_9	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_defaultConfig_18[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode__defaultConfig, defaultConfigMode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DefaultConfigMode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"defaultConfigMode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode__defaultConfig, defaultConfigIdentity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DefaultConfigIdentity_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"defaultConfigIdentity"
		},
};
static const ber_tlv_tag_t asn_DEF_defaultConfig_tags_18[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_defaultConfig_tag2el_18[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* defaultConfigMode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* defaultConfigIdentity */
};
static asn_SEQUENCE_specifics_t asn_SPC_defaultConfig_specs_18 = {
	sizeof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode__defaultConfig),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode__defaultConfig, _asn_ctx),
	asn_MAP_defaultConfig_tag2el_18,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_defaultConfig_18 = {
	"defaultConfig",
	"defaultConfig",
	&asn_OP_SEQUENCE,
	asn_DEF_defaultConfig_tags_18,
	sizeof(asn_DEF_defaultConfig_tags_18)
		/sizeof(asn_DEF_defaultConfig_tags_18[0]) - 1, /* 1 */
	asn_DEF_defaultConfig_tags_18,	/* Same as above */
	sizeof(asn_DEF_defaultConfig_tags_18)
		/sizeof(asn_DEF_defaultConfig_tags_18[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_defaultConfig_18,
	2,	/* Elements count */
	&asn_SPC_defaultConfig_specs_18	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_preConfigMode_16[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode, choice.predefinedConfigIdentity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PredefinedConfigIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"predefinedConfigIdentity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode, choice.defaultConfig),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_defaultConfig_18,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"defaultConfig"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_preConfigMode_tag2el_16[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* predefinedConfigIdentity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* defaultConfig */
};
static asn_CHOICE_specifics_t asn_SPC_preConfigMode_specs_16 = {
	sizeof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode, _asn_ctx),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode, present),
	sizeof(((struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration__preConfigMode *)0)->present),
	asn_MAP_preConfigMode_tag2el_16,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_preConfigMode_16 = {
	"preConfigMode",
	"preConfigMode",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_preConfigMode_constr_16, &asn_PER_type_preConfigMode_constr_16, CHOICE_constraint },
	asn_MBR_preConfigMode_16,
	2,	/* Elements count */
	&asn_SPC_preConfigMode_specs_16	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_preconfiguration_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration, preConfigMode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_preConfigMode_16,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"preConfigMode"
		},
};
static const ber_tlv_tag_t asn_DEF_preconfiguration_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_preconfiguration_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* preConfigMode */
};
static asn_SEQUENCE_specifics_t asn_SPC_preconfiguration_specs_15 = {
	sizeof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode__preconfiguration, _asn_ctx),
	asn_MAP_preconfiguration_tag2el_15,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_preconfiguration_15 = {
	"preconfiguration",
	"preconfiguration",
	&asn_OP_SEQUENCE,
	asn_DEF_preconfiguration_tags_15,
	sizeof(asn_DEF_preconfiguration_tags_15)
		/sizeof(asn_DEF_preconfiguration_tags_15[0]) - 1, /* 1 */
	asn_DEF_preconfiguration_tags_15,	/* Same as above */
	sizeof(asn_DEF_preconfiguration_tags_15)
		/sizeof(asn_DEF_preconfiguration_tags_15[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_preconfiguration_15,
	1,	/* Elements count */
	&asn_SPC_preconfiguration_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_specificationMode_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode, choice.complete),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_complete_9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"complete"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode, choice.preconfiguration),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_preconfiguration_15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"preconfiguration"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_specificationMode_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* complete */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* preconfiguration */
};
static asn_CHOICE_specifics_t asn_SPC_specificationMode_specs_8 = {
	sizeof(struct RRCConnectionSetup_r5_IEs__specificationMode),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode, _asn_ctx),
	offsetof(struct RRCConnectionSetup_r5_IEs__specificationMode, present),
	sizeof(((struct RRCConnectionSetup_r5_IEs__specificationMode *)0)->present),
	asn_MAP_specificationMode_tag2el_8,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_specificationMode_8 = {
	"specificationMode",
	"specificationMode",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_specificationMode_constr_8, &asn_PER_type_specificationMode_constr_8, CHOICE_constraint },
	asn_MBR_specificationMode_8,
	2,	/* Elements count */
	&asn_SPC_specificationMode_specs_8	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_RRCConnectionSetup_r5_IEs_1[] = {
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetup_r5_IEs, activationTime),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"activationTime"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs, new_U_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_U_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-U-RNTI"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetup_r5_IEs, new_c_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_C_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-c-RNTI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs, rrc_StateIndicator),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_StateIndicator,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-StateIndicator"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs, utran_DRX_CycleLengthCoeff),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_DRX_CycleLengthCoefficient,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"utran-DRX-CycleLengthCoeff"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetup_r5_IEs, capabilityUpdateRequirement),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CapabilityUpdateRequirement_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"capabilityUpdateRequirement"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetup_r5_IEs, specificationMode),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_specificationMode_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"specificationMode"
		},
	{ ATF_POINTER, 5, offsetof(struct RRCConnectionSetup_r5_IEs, frequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"frequencyInfo"
		},
	{ ATF_POINTER, 4, offsetof(struct RRCConnectionSetup_r5_IEs, maxAllowedUL_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxAllowedUL_TX_Power,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxAllowedUL-TX-Power"
		},
	{ ATF_POINTER, 3, offsetof(struct RRCConnectionSetup_r5_IEs, ul_ChannelRequirement),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_UL_ChannelRequirement_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-ChannelRequirement"
		},
	{ ATF_POINTER, 2, offsetof(struct RRCConnectionSetup_r5_IEs, dl_CommonInformation),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CommonInformation_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CommonInformation"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetup_r5_IEs, dl_InformationPerRL_List),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_InformationPerRL_List_r5bis,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-InformationPerRL-List"
		},
};
static const int asn_MAP_RRCConnectionSetup_r5_IEs_oms_1[] = { 0, 2, 5, 7, 8, 9, 10, 11 };
static const ber_tlv_tag_t asn_DEF_RRCConnectionSetup_r5_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RRCConnectionSetup_r5_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* activationTime */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* new-U-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* new-c-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* rrc-StateIndicator */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* utran-DRX-CycleLengthCoeff */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* capabilityUpdateRequirement */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* specificationMode */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* frequencyInfo */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* maxAllowedUL-TX-Power */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* ul-ChannelRequirement */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* dl-CommonInformation */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 } /* dl-InformationPerRL-List */
};
asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionSetup_r5_IEs_specs_1 = {
	sizeof(struct RRCConnectionSetup_r5_IEs),
	offsetof(struct RRCConnectionSetup_r5_IEs, _asn_ctx),
	asn_MAP_RRCConnectionSetup_r5_IEs_tag2el_1,
	12,	/* Count of tags in the map */
	asn_MAP_RRCConnectionSetup_r5_IEs_oms_1,	/* Optional members */
	8, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetup_r5_IEs = {
	"RRCConnectionSetup-r5-IEs",
	"RRCConnectionSetup-r5-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_RRCConnectionSetup_r5_IEs_tags_1,
	sizeof(asn_DEF_RRCConnectionSetup_r5_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionSetup_r5_IEs_tags_1[0]), /* 1 */
	asn_DEF_RRCConnectionSetup_r5_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_RRCConnectionSetup_r5_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionSetup_r5_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RRCConnectionSetup_r5_IEs_1,
	12,	/* Elements count */
	&asn_SPC_RRCConnectionSetup_r5_IEs_specs_1	/* Additional specs */
};

