/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RRCConnectionRelease_H_
#define	_RRCConnectionRelease_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRCConnectionRelease-r3-IEs.h"
#include <BIT_STRING.h>
#include "RRCConnectionRelease-v690ext-IEs.h"
#include <constr_SEQUENCE.h>
#include "RRC-TransactionIdentifier.h"
#include "RRCConnectionRelease-r4-IEs.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RRCConnectionRelease_PR {
	RRCConnectionRelease_PR_NOTHING,	/* No components present */
	RRCConnectionRelease_PR_r3,
	RRCConnectionRelease_PR_later_than_r3
} RRCConnectionRelease_PR;
typedef enum RRCConnectionRelease__later_than_r3__criticalExtensions_PR {
	RRCConnectionRelease__later_than_r3__criticalExtensions_PR_NOTHING,	/* No components present */
	RRCConnectionRelease__later_than_r3__criticalExtensions_PR_r4,
	RRCConnectionRelease__later_than_r3__criticalExtensions_PR_criticalExtensions
} RRCConnectionRelease__later_than_r3__criticalExtensions_PR;

/* RRCConnectionRelease */
typedef struct RRCConnectionRelease {
	RRCConnectionRelease_PR present;
	union RRCConnectionRelease_u {
		struct RRCConnectionRelease__r3 {
			RRCConnectionRelease_r3_IEs_t	 rrcConnectionRelease_r3;
			struct RRCConnectionRelease__r3__laterNonCriticalExtensions {
				BIT_STRING_t	*rrcConnectionRelease_r3_add_ext	/* OPTIONAL */;
				struct RRCConnectionRelease__r3__laterNonCriticalExtensions__v690NonCriticalExtensions {
					RRCConnectionRelease_v690ext_IEs_t	 rrcConnectionRelease_v690ext;
					struct RRCConnectionRelease__r3__laterNonCriticalExtensions__v690NonCriticalExtensions__nonCriticalExtensions {
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *nonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *v690NonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *laterNonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct RRCConnectionRelease__later_than_r3 {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct RRCConnectionRelease__later_than_r3__criticalExtensions {
				RRCConnectionRelease__later_than_r3__criticalExtensions_PR present;
				union RRCConnectionRelease__later_than_r3__criticalExtensions_u {
					struct RRCConnectionRelease__later_than_r3__criticalExtensions__r4 {
						RRCConnectionRelease_r4_IEs_t	 rrcConnectionRelease_r4;
						struct RRCConnectionRelease__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions {
							BIT_STRING_t	*rrcConnectionRelease_r4_add_ext	/* OPTIONAL */;
							struct RRCConnectionRelease__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v690NonCriticalExtensions {
								RRCConnectionRelease_v690ext_IEs_t	 rrcConnectionRelease_v690ext;
								struct RRCConnectionRelease__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v690NonCriticalExtensions__nonCriticalExtensions {
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *nonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v690NonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v4d0NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} r4;
					struct RRCConnectionRelease__later_than_r3__criticalExtensions__criticalExtensions {
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} criticalExtensions;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} later_than_r3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionRelease_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionRelease;
extern asn_CHOICE_specifics_t asn_SPC_RRCConnectionRelease_specs_1;
extern asn_TYPE_member_t asn_MBR_RRCConnectionRelease_1[2];
extern asn_per_constraints_t asn_PER_type_RRCConnectionRelease_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RRCConnectionRelease_H_ */
#include <asn_internal.h>