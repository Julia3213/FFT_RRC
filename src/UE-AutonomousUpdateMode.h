/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_AutonomousUpdateMode_H_
#define	_UE_AutonomousUpdateMode_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "RL-InformationLists.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_AutonomousUpdateMode_PR {
	UE_AutonomousUpdateMode_PR_NOTHING,	/* No components present */
	UE_AutonomousUpdateMode_PR_dummy,
	UE_AutonomousUpdateMode_PR_onWithNoReporting,
	UE_AutonomousUpdateMode_PR_dummy2
} UE_AutonomousUpdateMode_PR;

/* UE-AutonomousUpdateMode */
typedef struct UE_AutonomousUpdateMode {
	UE_AutonomousUpdateMode_PR present;
	union UE_AutonomousUpdateMode_u {
		NULL_t	 dummy;
		NULL_t	 onWithNoReporting;
		RL_InformationLists_t	 dummy2;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_AutonomousUpdateMode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_AutonomousUpdateMode;
extern asn_CHOICE_specifics_t asn_SPC_UE_AutonomousUpdateMode_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_AutonomousUpdateMode_1[3];
extern asn_per_constraints_t asn_PER_type_UE_AutonomousUpdateMode_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_AutonomousUpdateMode_H_ */
#include <asn_internal.h>