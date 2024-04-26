/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_DPCH_PowerControlInfo_r7_H_
#define	_UL_DPCH_PowerControlInfo_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DPCCH-PowerOffset.h"
#include "PC-Preamble.h"
#include "SRB-delay.h"
#include "PowerControlAlgorithm.h"
#include "DeltaACK.h"
#include "DeltaNACK.h"
#include "ACK-NACK-repetitionFactor.h"
#include "HARQ-Preamble-Mode.h"
#include <constr_SEQUENCE.h>
#include "UL-TargetSIR.h"
#include <NULL.h>
#include "PrimaryCCPCH-TX-Power.h"
#include "IndividualTS-InterferenceList.h"
#include "ConstantValue.h"
#include "BEACON-PL-Est.h"
#include "TPC-StepSizeTDD.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_DPCH_PowerControlInfo_r7_PR {
	UL_DPCH_PowerControlInfo_r7_PR_NOTHING,	/* No components present */
	UL_DPCH_PowerControlInfo_r7_PR_fdd,
	UL_DPCH_PowerControlInfo_r7_PR_tdd
} UL_DPCH_PowerControlInfo_r7_PR;
typedef enum UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_PR {
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_PR_NOTHING,	/* No components present */
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_PR_broadcast_UL_OL_PC_info,
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_PR_individuallySignalled
} UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_PR;
typedef enum UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR {
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR_NOTHING,	/* No components present */
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR_tdd384,
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR_tdd768,
	UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR_tdd128
} UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR;

/* UL-DPCH-PowerControlInfo-r7 */
typedef struct UL_DPCH_PowerControlInfo_r7 {
	UL_DPCH_PowerControlInfo_r7_PR present;
	union UL_DPCH_PowerControlInfo_r7_u {
		struct UL_DPCH_PowerControlInfo_r7__fdd {
			DPCCH_PowerOffset_t	 dpcch_PowerOffset;
			PC_Preamble_t	 pc_Preamble;
			SRB_delay_t	 sRB_delay;
			PowerControlAlgorithm_t	 powerControlAlgorithm;
			DeltaACK_t	*deltaACK	/* OPTIONAL */;
			DeltaNACK_t	*deltaNACK	/* OPTIONAL */;
			ACK_NACK_repetitionFactor_t	*ack_NACK_repetition_factor	/* OPTIONAL */;
			HARQ_Preamble_Mode_t	 harq_Preamble_Mode;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} fdd;
		struct UL_DPCH_PowerControlInfo_r7__tdd {
			UL_TargetSIR_t	*ul_TargetSIR	/* OPTIONAL */;
			struct UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling {
				UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_PR present;
				union UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling_u {
					NULL_t	 broadcast_UL_OL_PC_info;
					struct UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled {
						struct UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption {
							UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_PR present;
							union UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption_u {
								struct UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd384 {
									IndividualTS_InterferenceList_t	 individualTS_InterferenceList;
									ConstantValue_t	 dpch_ConstantValue;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} tdd384;
								struct UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd768 {
									IndividualTS_InterferenceList_t	 individualTS_InterferenceList;
									ConstantValue_t	 dpch_ConstantValue;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} tdd768;
								struct UL_DPCH_PowerControlInfo_r7__tdd__ul_OL_PC_Signalling__individuallySignalled__tddOption__tdd128 {
									BEACON_PL_Est_t	*beaconPLEst	/* OPTIONAL */;
									TPC_StepSizeTDD_t	 tpc_StepSize;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} tdd128;
							} choice;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} tddOption;
						PrimaryCCPCH_TX_Power_t	 primaryCCPCH_TX_Power;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} individuallySignalled;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} ul_OL_PC_Signalling;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} tdd;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_DPCH_PowerControlInfo_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_DPCH_PowerControlInfo_r7;
extern asn_CHOICE_specifics_t asn_SPC_UL_DPCH_PowerControlInfo_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_DPCH_PowerControlInfo_r7_1[2];
extern asn_per_constraints_t asn_PER_type_UL_DPCH_PowerControlInfo_r7_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_DPCH_PowerControlInfo_r7_H_ */
#include <asn_internal.h>
