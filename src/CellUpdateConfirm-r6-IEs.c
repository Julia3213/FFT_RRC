/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "CellUpdateConfirm-r6-IEs.h"

#include "IntegrityProtectionModeInfo.h"
#include "CipheringModeInfo.h"
#include "U-RNTI.h"
#include "CN-InformationInfo-r6.h"
#include "RB-InformationReleaseList.h"
#include "RB-InformationReconfigList-r6.h"
#include "RB-InformationAffectedList-r6.h"
#include "DL-CounterSynchronisationInfo-r5.h"
#include "UL-CommonTransChInfo-r4.h"
#include "UL-DeletedTransChInfoList-r6.h"
#include "UL-AddReconfTransChInfoList-r6.h"
#include "DL-CommonTransChInfo-r4.h"
#include "DL-DeletedTransChInfoList-r5.h"
#include "DL-AddReconfTransChInfoList-r5.h"
#include "FrequencyInfo.h"
#include "UL-DPCH-Info-r6.h"
#include "UL-EDCH-Information-r6.h"
#include "DL-HSPDSCH-Information-r6.h"
#include "DL-CommonInformation-r6.h"
#include "DL-InformationPerRL-List-r6.h"
asn_TYPE_member_t asn_MBR_CellUpdateConfirm_r6_IEs_1[] = {
	{ ATF_POINTER, 9, offsetof(struct CellUpdateConfirm_r6_IEs, integrityProtectionModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtectionModeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"integrityProtectionModeInfo"
		},
	{ ATF_POINTER, 8, offsetof(struct CellUpdateConfirm_r6_IEs, cipheringModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CipheringModeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cipheringModeInfo"
		},
	{ ATF_POINTER, 7, offsetof(struct CellUpdateConfirm_r6_IEs, activationTime),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"activationTime"
		},
	{ ATF_POINTER, 6, offsetof(struct CellUpdateConfirm_r6_IEs, new_U_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_U_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-U-RNTI"
		},
	{ ATF_POINTER, 5, offsetof(struct CellUpdateConfirm_r6_IEs, new_C_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_C_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-C-RNTI"
		},
	{ ATF_POINTER, 4, offsetof(struct CellUpdateConfirm_r6_IEs, new_DSCH_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DSCH_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-DSCH-RNTI"
		},
	{ ATF_POINTER, 3, offsetof(struct CellUpdateConfirm_r6_IEs, new_H_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_H_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"new-H-RNTI"
		},
	{ ATF_POINTER, 2, offsetof(struct CellUpdateConfirm_r6_IEs, newPrimary_E_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"newPrimary-E-RNTI"
		},
	{ ATF_POINTER, 1, offsetof(struct CellUpdateConfirm_r6_IEs, newSecondary_E_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RNTI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"newSecondary-E-RNTI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellUpdateConfirm_r6_IEs, rrc_StateIndicator),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_StateIndicator,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-StateIndicator"
		},
	{ ATF_POINTER, 1, offsetof(struct CellUpdateConfirm_r6_IEs, utran_DRX_CycleLengthCoeff),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_DRX_CycleLengthCoefficient,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"utran-DRX-CycleLengthCoeff"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellUpdateConfirm_r6_IEs, rlc_Re_establishIndicatorRb2_3or4),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rlc-Re-establishIndicatorRb2-3or4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellUpdateConfirm_r6_IEs, rlc_Re_establishIndicatorRb5orAbove),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rlc-Re-establishIndicatorRb5orAbove"
		},
	{ ATF_POINTER, 21, offsetof(struct CellUpdateConfirm_r6_IEs, cn_InformationInfo),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CN_InformationInfo_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cn-InformationInfo"
		},
	{ ATF_POINTER, 20, offsetof(struct CellUpdateConfirm_r6_IEs, ura_Identity),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_URA_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ura-Identity"
		},
	{ ATF_POINTER, 19, offsetof(struct CellUpdateConfirm_r6_IEs, rb_InformationReleaseList),
		(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_InformationReleaseList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rb-InformationReleaseList"
		},
	{ ATF_POINTER, 18, offsetof(struct CellUpdateConfirm_r6_IEs, rb_InformationReconfigList),
		(ASN_TAG_CLASS_CONTEXT | (16 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_InformationReconfigList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rb-InformationReconfigList"
		},
	{ ATF_POINTER, 17, offsetof(struct CellUpdateConfirm_r6_IEs, rb_InformationAffectedList),
		(ASN_TAG_CLASS_CONTEXT | (17 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_InformationAffectedList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rb-InformationAffectedList"
		},
	{ ATF_POINTER, 16, offsetof(struct CellUpdateConfirm_r6_IEs, dl_CounterSynchronisationInfo),
		(ASN_TAG_CLASS_CONTEXT | (18 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CounterSynchronisationInfo_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CounterSynchronisationInfo"
		},
	{ ATF_POINTER, 15, offsetof(struct CellUpdateConfirm_r6_IEs, pdcp_ROHC_TargetMode),
		(ASN_TAG_CLASS_CONTEXT | (19 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PDCP_ROHC_TargetMode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pdcp-ROHC-TargetMode"
		},
	{ ATF_POINTER, 14, offsetof(struct CellUpdateConfirm_r6_IEs, ul_CommonTransChInfo),
		(ASN_TAG_CLASS_CONTEXT | (20 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_CommonTransChInfo_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-CommonTransChInfo"
		},
	{ ATF_POINTER, 13, offsetof(struct CellUpdateConfirm_r6_IEs, ul_deletedTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (21 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_DeletedTransChInfoList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-deletedTransChInfoList"
		},
	{ ATF_POINTER, 12, offsetof(struct CellUpdateConfirm_r6_IEs, ul_AddReconfTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (22 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_AddReconfTransChInfoList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-AddReconfTransChInfoList"
		},
	{ ATF_POINTER, 11, offsetof(struct CellUpdateConfirm_r6_IEs, dl_CommonTransChInfo),
		(ASN_TAG_CLASS_CONTEXT | (23 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CommonTransChInfo_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CommonTransChInfo"
		},
	{ ATF_POINTER, 10, offsetof(struct CellUpdateConfirm_r6_IEs, dl_DeletedTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (24 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_DeletedTransChInfoList_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-DeletedTransChInfoList"
		},
	{ ATF_POINTER, 9, offsetof(struct CellUpdateConfirm_r6_IEs, dl_AddReconfTransChInfoList),
		(ASN_TAG_CLASS_CONTEXT | (25 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_AddReconfTransChInfoList_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-AddReconfTransChInfoList"
		},
	{ ATF_POINTER, 8, offsetof(struct CellUpdateConfirm_r6_IEs, frequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (26 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"frequencyInfo"
		},
	{ ATF_POINTER, 7, offsetof(struct CellUpdateConfirm_r6_IEs, maxAllowedUL_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (27 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxAllowedUL_TX_Power,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxAllowedUL-TX-Power"
		},
	{ ATF_POINTER, 6, offsetof(struct CellUpdateConfirm_r6_IEs, ul_DPCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (28 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_DPCH_Info_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-DPCH-Info"
		},
	{ ATF_POINTER, 5, offsetof(struct CellUpdateConfirm_r6_IEs, ul_EDCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (29 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_EDCH_Information_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-EDCH-Information"
		},
	{ ATF_POINTER, 4, offsetof(struct CellUpdateConfirm_r6_IEs, dl_HSPDSCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (30 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_HSPDSCH_Information_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-HSPDSCH-Information"
		},
	{ ATF_POINTER, 3, offsetof(struct CellUpdateConfirm_r6_IEs, dl_CommonInformation),
		(ASN_TAG_CLASS_CONTEXT | (31 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CommonInformation_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CommonInformation"
		},
	{ ATF_POINTER, 2, offsetof(struct CellUpdateConfirm_r6_IEs, dl_InformationPerRL_List),
		(ASN_TAG_CLASS_CONTEXT | (32 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_InformationPerRL_List_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-InformationPerRL-List"
		},
	{ ATF_POINTER, 1, offsetof(struct CellUpdateConfirm_r6_IEs, mbms_PL_ServiceRestrictInfo),
		(ASN_TAG_CLASS_CONTEXT | (33 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_PL_ServiceRestrictInfo_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-PL-ServiceRestrictInfo"
		},
};
static const int asn_MAP_CellUpdateConfirm_r6_IEs_oms_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 };
static const ber_tlv_tag_t asn_DEF_CellUpdateConfirm_r6_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CellUpdateConfirm_r6_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* integrityProtectionModeInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cipheringModeInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* activationTime */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* new-U-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* new-C-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* new-DSCH-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* new-H-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* newPrimary-E-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* newSecondary-E-RNTI */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* rrc-StateIndicator */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* utran-DRX-CycleLengthCoeff */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* rlc-Re-establishIndicatorRb2-3or4 */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* rlc-Re-establishIndicatorRb5orAbove */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* cn-InformationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 14, 0, 0 }, /* ura-Identity */
    { (ASN_TAG_CLASS_CONTEXT | (15 << 2)), 15, 0, 0 }, /* rb-InformationReleaseList */
    { (ASN_TAG_CLASS_CONTEXT | (16 << 2)), 16, 0, 0 }, /* rb-InformationReconfigList */
    { (ASN_TAG_CLASS_CONTEXT | (17 << 2)), 17, 0, 0 }, /* rb-InformationAffectedList */
    { (ASN_TAG_CLASS_CONTEXT | (18 << 2)), 18, 0, 0 }, /* dl-CounterSynchronisationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (19 << 2)), 19, 0, 0 }, /* pdcp-ROHC-TargetMode */
    { (ASN_TAG_CLASS_CONTEXT | (20 << 2)), 20, 0, 0 }, /* ul-CommonTransChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (21 << 2)), 21, 0, 0 }, /* ul-deletedTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (22 << 2)), 22, 0, 0 }, /* ul-AddReconfTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (23 << 2)), 23, 0, 0 }, /* dl-CommonTransChInfo */
    { (ASN_TAG_CLASS_CONTEXT | (24 << 2)), 24, 0, 0 }, /* dl-DeletedTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (25 << 2)), 25, 0, 0 }, /* dl-AddReconfTransChInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (26 << 2)), 26, 0, 0 }, /* frequencyInfo */
    { (ASN_TAG_CLASS_CONTEXT | (27 << 2)), 27, 0, 0 }, /* maxAllowedUL-TX-Power */
    { (ASN_TAG_CLASS_CONTEXT | (28 << 2)), 28, 0, 0 }, /* ul-DPCH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (29 << 2)), 29, 0, 0 }, /* ul-EDCH-Information */
    { (ASN_TAG_CLASS_CONTEXT | (30 << 2)), 30, 0, 0 }, /* dl-HSPDSCH-Information */
    { (ASN_TAG_CLASS_CONTEXT | (31 << 2)), 31, 0, 0 }, /* dl-CommonInformation */
    { (ASN_TAG_CLASS_CONTEXT | (32 << 2)), 32, 0, 0 }, /* dl-InformationPerRL-List */
    { (ASN_TAG_CLASS_CONTEXT | (33 << 2)), 33, 0, 0 } /* mbms-PL-ServiceRestrictInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_CellUpdateConfirm_r6_IEs_specs_1 = {
	sizeof(struct CellUpdateConfirm_r6_IEs),
	offsetof(struct CellUpdateConfirm_r6_IEs, _asn_ctx),
	asn_MAP_CellUpdateConfirm_r6_IEs_tag2el_1,
	34,	/* Count of tags in the map */
	asn_MAP_CellUpdateConfirm_r6_IEs_oms_1,	/* Optional members */
	31, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CellUpdateConfirm_r6_IEs = {
	"CellUpdateConfirm-r6-IEs",
	"CellUpdateConfirm-r6-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_CellUpdateConfirm_r6_IEs_tags_1,
	sizeof(asn_DEF_CellUpdateConfirm_r6_IEs_tags_1)
		/sizeof(asn_DEF_CellUpdateConfirm_r6_IEs_tags_1[0]), /* 1 */
	asn_DEF_CellUpdateConfirm_r6_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_CellUpdateConfirm_r6_IEs_tags_1)
		/sizeof(asn_DEF_CellUpdateConfirm_r6_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CellUpdateConfirm_r6_IEs_1,
	34,	/* Elements count */
	&asn_SPC_CellUpdateConfirm_r6_IEs_specs_1	/* Additional specs */
};

