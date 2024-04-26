/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PUSCH_CapacityAllocationInfo_r7_H_
#define	_PUSCH_CapacityAllocationInfo_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "AllocationPeriodInfo.h"
#include "TFCS-IdentityPlain.h"
#include "PUSCH-Identity.h"
#include <constr_SEQUENCE.h>
#include "PUSCH-Info-VHCR.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_PR {
	PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_PR_NOTHING,	/* No components present */
	PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_PR_pusch_AllocationPending,
	PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_PR_pusch_AllocationAssignment
} PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_PR;
typedef enum PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_PR {
	PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_PR_NOTHING,	/* No components present */
	PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_PR_old_Configuration,
	PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_PR_new_Configuration
} PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_PR;

/* Forward declarations */
struct PUSCH_PowerControlInfo_r7;

/* PUSCH-CapacityAllocationInfo-r7 */
typedef struct PUSCH_CapacityAllocationInfo_r7 {
	struct PUSCH_CapacityAllocationInfo_r7__pusch_Allocation {
		PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_PR present;
		union PUSCH_CapacityAllocationInfo_r7__pusch_Allocation_u {
			NULL_t	 pusch_AllocationPending;
			struct PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment {
				AllocationPeriodInfo_t	 pusch_AllocationPeriodInfo;
				struct PUSCH_PowerControlInfo_r7	*pusch_PowerControlInfo	/* OPTIONAL */;
				struct PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration {
					PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_PR present;
					union PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration_u {
						struct PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration__old_Configuration {
							TFCS_IdentityPlain_t	*tfcs_ID	/* DEFAULT 1 */;
							PUSCH_Identity_t	 pusch_Identity;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} old_Configuration;
						struct PUSCH_CapacityAllocationInfo_r7__pusch_Allocation__pusch_AllocationAssignment__configuration__new_Configuration {
							PUSCH_Info_VHCR_t	 pusch_Info;
							PUSCH_Identity_t	*pusch_Identity	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} new_Configuration;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} configuration;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} pusch_AllocationAssignment;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} pusch_Allocation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PUSCH_CapacityAllocationInfo_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PUSCH_CapacityAllocationInfo_r7;
extern asn_SEQUENCE_specifics_t asn_SPC_PUSCH_CapacityAllocationInfo_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_PUSCH_CapacityAllocationInfo_r7_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _PUSCH_CapacityAllocationInfo_r7_H_ */
#include <asn_internal.h>
