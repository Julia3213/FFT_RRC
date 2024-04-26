/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_DPCH_InfoCommon_r4_H_
#define	_DL_DPCH_InfoCommon_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MAC-d-HFN-initial-value.h"
#include <NULL.h>
#include "Cfntargetsfnframeoffset.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>
#include "PowerOffsetPilot-pdpdch.h"
#include "SF512-AndPilot.h"
#include "PositionFixedOrFlexible.h"
#include <BOOLEAN.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_DPCH_InfoCommon_r4__cfnHandling_PR {
	DL_DPCH_InfoCommon_r4__cfnHandling_PR_NOTHING,	/* No components present */
	DL_DPCH_InfoCommon_r4__cfnHandling_PR_maintain,
	DL_DPCH_InfoCommon_r4__cfnHandling_PR_initialise
} DL_DPCH_InfoCommon_r4__cfnHandling_PR;
typedef enum DL_DPCH_InfoCommon_r4__modeSpecificInfo_PR {
	DL_DPCH_InfoCommon_r4__modeSpecificInfo_PR_NOTHING,	/* No components present */
	DL_DPCH_InfoCommon_r4__modeSpecificInfo_PR_fdd,
	DL_DPCH_InfoCommon_r4__modeSpecificInfo_PR_tdd
} DL_DPCH_InfoCommon_r4__modeSpecificInfo_PR;

/* Forward declarations */
struct DL_DPCH_PowerControlInfo;
struct Dl_rate_matching_restriction;

/* DL-DPCH-InfoCommon-r4 */
typedef struct DL_DPCH_InfoCommon_r4 {
	struct DL_DPCH_InfoCommon_r4__cfnHandling {
		DL_DPCH_InfoCommon_r4__cfnHandling_PR present;
		union DL_DPCH_InfoCommon_r4__cfnHandling_u {
			NULL_t	 maintain;
			struct DL_DPCH_InfoCommon_r4__cfnHandling__initialise {
				Cfntargetsfnframeoffset_t	*dummy	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} initialise;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} cfnHandling;
	struct DL_DPCH_InfoCommon_r4__modeSpecificInfo {
		DL_DPCH_InfoCommon_r4__modeSpecificInfo_PR present;
		union DL_DPCH_InfoCommon_r4__modeSpecificInfo_u {
			struct DL_DPCH_InfoCommon_r4__modeSpecificInfo__fdd {
				struct DL_DPCH_PowerControlInfo	*dl_DPCH_PowerControlInfo	/* OPTIONAL */;
				PowerOffsetPilot_pdpdch_t	 powerOffsetPilot_pdpdch;
				struct Dl_rate_matching_restriction	*dl_rate_matching_restriction	/* OPTIONAL */;
				SF512_AndPilot_t	 spreadingFactorAndPilot;
				PositionFixedOrFlexible_t	 positionFixedOrFlexible;
				BOOLEAN_t	 tfci_Existence;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct DL_DPCH_InfoCommon_r4__modeSpecificInfo__tdd {
				struct DL_DPCH_PowerControlInfo	*dl_DPCH_PowerControlInfo	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	MAC_d_HFN_initial_value_t	*mac_d_HFN_initial_value	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_DPCH_InfoCommon_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_DPCH_InfoCommon_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_DL_DPCH_InfoCommon_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_DPCH_InfoCommon_r4_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _DL_DPCH_InfoCommon_r4_H_ */
#include <asn_internal.h>
