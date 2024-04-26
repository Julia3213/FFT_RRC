/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RadioBearerSetup_r6_IEs_H_
#define	_RadioBearerSetup_r6_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ActivationTime.h"
#include "C-RNTI.h"
#include "DSCH-RNTI.h"
#include "H-RNTI.h"
#include "E-RNTI.h"
#include "RRC-StateIndicator.h"
#include "UTRAN-DRX-CycleLengthCoefficient.h"
#include "URA-Identity.h"
#include "MaxAllowedUL-TX-Power.h"
#include "MBMS-PL-ServiceRestrictInfo-r6.h"
#include "PDCP-ROHC-TargetMode.h"
#include <constr_SEQUENCE.h>
#include "RAB-Info-r6.h"
#include "DefaultConfigMode.h"
#include "DefaultConfigIdentity-r6.h"
#include "PowerOffsetInfoShort.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RadioBearerSetup_r6_IEs__specificationMode_PR {
	RadioBearerSetup_r6_IEs__specificationMode_PR_NOTHING,	/* No components present */
	RadioBearerSetup_r6_IEs__specificationMode_PR_complete,
	RadioBearerSetup_r6_IEs__specificationMode_PR_preconfiguration
} RadioBearerSetup_r6_IEs__specificationMode_PR;

/* Forward declarations */
struct IntegrityProtectionModeInfo;
struct CipheringModeInfo;
struct U_RNTI;
struct CN_InformationInfo_r6;
struct FrequencyInfo;
struct UL_DPCH_Info_r6;
struct UL_EDCH_Information_r6;
struct DL_HSPDSCH_Information_r6;
struct DL_CommonInformation_r6;
struct DL_InformationPerRL_List_r6;
struct SRB_InformationSetupList_r6;
struct RAB_InformationSetupList_r6;
struct RAB_InformationReconfigList;
struct RB_InformationReconfigList_r6;
struct RB_InformationAffectedList_r6;
struct DL_CounterSynchronisationInfo_r5;
struct UL_CommonTransChInfo_r4;
struct UL_DeletedTransChInfoList_r6;
struct UL_AddReconfTransChInfoList_r6;
struct DL_CommonTransChInfo_r4;
struct DL_DeletedTransChInfoList_r5;
struct DL_AddReconfTransChInfoList_r5;
struct RB_InformationChangedList_r6;

/* RadioBearerSetup-r6-IEs */
typedef struct RadioBearerSetup_r6_IEs {
	struct IntegrityProtectionModeInfo	*integrityProtectionModeInfo	/* OPTIONAL */;
	struct CipheringModeInfo	*cipheringModeInfo	/* OPTIONAL */;
	ActivationTime_t	*activationTime	/* OPTIONAL */;
	struct U_RNTI	*new_U_RNTI	/* OPTIONAL */;
	C_RNTI_t	*new_C_RNTI	/* OPTIONAL */;
	DSCH_RNTI_t	*new_DSCH_RNTI	/* OPTIONAL */;
	H_RNTI_t	*new_H_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newPrimary_E_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newSecondary_E_RNTI	/* OPTIONAL */;
	RRC_StateIndicator_t	 rrc_StateIndicator;
	UTRAN_DRX_CycleLengthCoefficient_t	*utran_DRX_CycleLengthCoeff	/* OPTIONAL */;
	URA_Identity_t	*ura_Identity	/* OPTIONAL */;
	struct CN_InformationInfo_r6	*cn_InformationInfo	/* OPTIONAL */;
	struct RadioBearerSetup_r6_IEs__specificationMode {
		RadioBearerSetup_r6_IEs__specificationMode_PR present;
		union RadioBearerSetup_r6_IEs__specificationMode_u {
			struct RadioBearerSetup_r6_IEs__specificationMode__complete {
				struct SRB_InformationSetupList_r6	*srb_InformationSetupList	/* OPTIONAL */;
				struct RAB_InformationSetupList_r6	*rab_InformationSetupList	/* OPTIONAL */;
				struct RAB_InformationReconfigList	*rab_InformationReconfigList	/* OPTIONAL */;
				struct RB_InformationReconfigList_r6	*rb_InformationReconfigList	/* OPTIONAL */;
				struct RB_InformationAffectedList_r6	*rb_InformationAffectedList	/* OPTIONAL */;
				struct DL_CounterSynchronisationInfo_r5	*dl_CounterSynchronisationInfo	/* OPTIONAL */;
				PDCP_ROHC_TargetMode_t	*pdcp_ROHC_TargetMode	/* OPTIONAL */;
				struct UL_CommonTransChInfo_r4	*ul_CommonTransChInfo	/* OPTIONAL */;
				struct UL_DeletedTransChInfoList_r6	*ul_deletedTransChInfoList	/* OPTIONAL */;
				struct UL_AddReconfTransChInfoList_r6	*ul_AddReconfTransChInfoList	/* OPTIONAL */;
				struct DL_CommonTransChInfo_r4	*dl_CommonTransChInfo	/* OPTIONAL */;
				struct DL_DeletedTransChInfoList_r5	*dl_DeletedTransChInfoList	/* OPTIONAL */;
				struct DL_AddReconfTransChInfoList_r5	*dl_AddReconfTransChInfoList	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} complete;
			struct RadioBearerSetup_r6_IEs__specificationMode__preconfiguration {
				RAB_Info_r6_t	 rab_Info;
				DefaultConfigMode_t	 defaultConfigMode;
				DefaultConfigIdentity_r6_t	 defaultConfigIdentity;
				struct RB_InformationChangedList_r6	*rb_InformationChangedList	/* OPTIONAL */;
				PowerOffsetInfoShort_t	 powerOffsetInfoShort;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} preconfiguration;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} specificationMode;
	struct FrequencyInfo	*frequencyInfo	/* OPTIONAL */;
	MaxAllowedUL_TX_Power_t	*maxAllowedUL_TX_Power	/* OPTIONAL */;
	struct UL_DPCH_Info_r6	*ul_DPCH_Info	/* OPTIONAL */;
	struct UL_EDCH_Information_r6	*ul_EDCH_Information	/* OPTIONAL */;
	struct DL_HSPDSCH_Information_r6	*dl_HSPDSCH_Information	/* OPTIONAL */;
	struct DL_CommonInformation_r6	*dl_CommonInformation	/* OPTIONAL */;
	struct DL_InformationPerRL_List_r6	*dl_InformationPerRL_List	/* OPTIONAL */;
	MBMS_PL_ServiceRestrictInfo_r6_t	*mbms_PL_ServiceRestrictInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadioBearerSetup_r6_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadioBearerSetup_r6_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RadioBearerSetup_r6_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_RadioBearerSetup_r6_IEs_1[22];

#ifdef __cplusplus
}
#endif

#endif	/* _RadioBearerSetup_r6_IEs_H_ */
#include <asn_internal.h>