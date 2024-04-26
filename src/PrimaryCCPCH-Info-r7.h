/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PrimaryCCPCH_Info_r7_H_
#define	_PrimaryCCPCH_Info_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>
#include "CellParametersID.h"
#include "TimeslotNumber.h"
#include "TimeslotSync2.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PrimaryCCPCH_Info_r7_PR {
	PrimaryCCPCH_Info_r7_PR_NOTHING,	/* No components present */
	PrimaryCCPCH_Info_r7_PR_fdd,
	PrimaryCCPCH_Info_r7_PR_tdd
} PrimaryCCPCH_Info_r7_PR;
typedef enum PrimaryCCPCH_Info_r7__tdd__tddOption_PR {
	PrimaryCCPCH_Info_r7__tdd__tddOption_PR_NOTHING,	/* No components present */
	PrimaryCCPCH_Info_r7__tdd__tddOption_PR_tdd384,
	PrimaryCCPCH_Info_r7__tdd__tddOption_PR_tdd768,
	PrimaryCCPCH_Info_r7__tdd__tddOption_PR_tdd128
} PrimaryCCPCH_Info_r7__tdd__tddOption_PR;
typedef enum PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_PR {
	PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_PR_NOTHING,	/* No components present */
	PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_PR_syncCase1,
	PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_PR_syncCase2
} PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_PR;
typedef enum PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_PR {
	PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_PR_NOTHING,	/* No components present */
	PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_PR_syncCase1,
	PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_PR_syncCase2
} PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_PR;

/* PrimaryCCPCH-Info-r7 */
typedef struct PrimaryCCPCH_Info_r7 {
	PrimaryCCPCH_Info_r7_PR present;
	union PrimaryCCPCH_Info_r7_u {
		struct PrimaryCCPCH_Info_r7__fdd {
			BOOLEAN_t	 tx_DiversityIndicator;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} fdd;
		struct PrimaryCCPCH_Info_r7__tdd {
			struct PrimaryCCPCH_Info_r7__tdd__tddOption {
				PrimaryCCPCH_Info_r7__tdd__tddOption_PR present;
				union PrimaryCCPCH_Info_r7__tdd__tddOption_u {
					struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384 {
						struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase {
							PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_PR present;
							union PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase_u {
								struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase__syncCase1 {
									TimeslotNumber_t	 timeslot;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} syncCase1;
								struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd384__syncCase__syncCase2 {
									TimeslotSync2_t	 timeslotSync2;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} syncCase2;
							} choice;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *syncCase;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} tdd384;
					struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768 {
						struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase {
							PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_PR present;
							union PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase_u {
								struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase__syncCase1 {
									TimeslotNumber_t	 timeslot;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} syncCase1;
								struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd768__syncCase__syncCase2 {
									TimeslotSync2_t	 timeslotSync2;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} syncCase2;
							} choice;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *syncCase;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} tdd768;
					struct PrimaryCCPCH_Info_r7__tdd__tddOption__tdd128 {
						BOOLEAN_t	 tstd_Indicator;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} tdd128;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tddOption;
			CellParametersID_t	*cellParametersID	/* OPTIONAL */;
			BOOLEAN_t	 sctd_Indicator;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} tdd;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PrimaryCCPCH_Info_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PrimaryCCPCH_Info_r7;
extern asn_CHOICE_specifics_t asn_SPC_PrimaryCCPCH_Info_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_PrimaryCCPCH_Info_r7_1[2];
extern asn_per_constraints_t asn_PER_type_PrimaryCCPCH_Info_r7_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PrimaryCCPCH_Info_r7_H_ */
#include <asn_internal.h>
