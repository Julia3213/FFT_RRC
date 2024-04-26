/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CounterCheck_H_
#define	_CounterCheck_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CounterCheck-r3-IEs.h"
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>
#include "RRC-TransactionIdentifier.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CounterCheck_PR {
	CounterCheck_PR_NOTHING,	/* No components present */
	CounterCheck_PR_r3,
	CounterCheck_PR_later_than_r3
} CounterCheck_PR;

/* CounterCheck */
typedef struct CounterCheck {
	CounterCheck_PR present;
	union CounterCheck_u {
		struct CounterCheck__r3 {
			CounterCheck_r3_IEs_t	 counterCheck_r3;
			struct CounterCheck__r3__laterNonCriticalExtensions {
				BIT_STRING_t	*counterCheck_r3_add_ext	/* OPTIONAL */;
				struct CounterCheck__r3__laterNonCriticalExtensions__nonCriticalExtensions {
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *nonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *laterNonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct CounterCheck__later_than_r3 {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct CounterCheck__later_than_r3__criticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} later_than_r3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CounterCheck_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CounterCheck;
extern asn_CHOICE_specifics_t asn_SPC_CounterCheck_specs_1;
extern asn_TYPE_member_t asn_MBR_CounterCheck_1[2];
extern asn_per_constraints_t asn_PER_type_CounterCheck_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _CounterCheck_H_ */
#include <asn_internal.h>
