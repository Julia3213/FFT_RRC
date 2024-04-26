/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_TimingAdvanceControl_H_
#define	_UL_TimingAdvanceControl_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "UL-TimingAdvance.h"
#include "ActivationTime.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_TimingAdvanceControl_PR {
	UL_TimingAdvanceControl_PR_NOTHING,	/* No components present */
	UL_TimingAdvanceControl_PR_disabled,
	UL_TimingAdvanceControl_PR_enabled
} UL_TimingAdvanceControl_PR;

/* UL-TimingAdvanceControl */
typedef struct UL_TimingAdvanceControl {
	UL_TimingAdvanceControl_PR present;
	union UL_TimingAdvanceControl_u {
		NULL_t	 disabled;
		struct UL_TimingAdvanceControl__enabled {
			UL_TimingAdvance_t	*ul_TimingAdvance	/* OPTIONAL */;
			ActivationTime_t	*activationTime	/* OPTIONAL */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} enabled;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_TimingAdvanceControl_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_TimingAdvanceControl;
extern asn_CHOICE_specifics_t asn_SPC_UL_TimingAdvanceControl_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_TimingAdvanceControl_1[2];
extern asn_per_constraints_t asn_PER_type_UL_TimingAdvanceControl_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_TimingAdvanceControl_H_ */
#include <asn_internal.h>
