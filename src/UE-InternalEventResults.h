/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_InternalEventResults_H_
#define	_UE_InternalEventResults_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "PrimaryCPICH-Info.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_InternalEventResults_PR {
	UE_InternalEventResults_PR_NOTHING,	/* No components present */
	UE_InternalEventResults_PR_event6a,
	UE_InternalEventResults_PR_event6b,
	UE_InternalEventResults_PR_event6c,
	UE_InternalEventResults_PR_event6d,
	UE_InternalEventResults_PR_event6e,
	UE_InternalEventResults_PR_event6f,
	UE_InternalEventResults_PR_event6g,
	UE_InternalEventResults_PR_spare
} UE_InternalEventResults_PR;

/* UE-InternalEventResults */
typedef struct UE_InternalEventResults {
	UE_InternalEventResults_PR present;
	union UE_InternalEventResults_u {
		NULL_t	 event6a;
		NULL_t	 event6b;
		NULL_t	 event6c;
		NULL_t	 event6d;
		NULL_t	 event6e;
		PrimaryCPICH_Info_t	 event6f;
		PrimaryCPICH_Info_t	 event6g;
		NULL_t	 spare;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_InternalEventResults_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_InternalEventResults;
extern asn_CHOICE_specifics_t asn_SPC_UE_InternalEventResults_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_InternalEventResults_1[8];
extern asn_per_constraints_t asn_PER_type_UE_InternalEventResults_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_InternalEventResults_H_ */
#include <asn_internal.h>
