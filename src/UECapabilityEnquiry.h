/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UECapabilityEnquiry_H_
#define	_UECapabilityEnquiry_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UECapabilityEnquiry-r3-IEs.h"
#include <BIT_STRING.h>
#include "UECapabilityEnquiry-v4b0ext-IEs.h"
#include "UECapabilityEnquiry-v590ext-IEs.h"
#include "UECapabilityEnquiry-v7xyext-IEs.h"
#include <constr_SEQUENCE.h>
#include "RRC-TransactionIdentifier.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UECapabilityEnquiry_PR {
	UECapabilityEnquiry_PR_NOTHING,	/* No components present */
	UECapabilityEnquiry_PR_r3,
	UECapabilityEnquiry_PR_later_than_r3
} UECapabilityEnquiry_PR;

/* UECapabilityEnquiry */
typedef struct UECapabilityEnquiry {
	UECapabilityEnquiry_PR present;
	union UECapabilityEnquiry_u {
		struct UECapabilityEnquiry__r3 {
			UECapabilityEnquiry_r3_IEs_t	 ueCapabilityEnquiry_r3;
			struct UECapabilityEnquiry__r3__laterNonCriticalExtensions {
				BIT_STRING_t	*ueCapabilityEnquiry_r3_add_ext	/* OPTIONAL */;
				struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions {
					UECapabilityEnquiry_v4b0ext_IEs_t	 ueCapabilityEnquiry_v4b0ext;
					struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions {
						UECapabilityEnquiry_v590ext_IEs_t	 ueCapabilityEnquiry_v590ext;
						struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v7xyNonCriticalExtensions {
							UECapabilityEnquiry_v7xyext_IEs_t	 ueCapabilityEnquiry_v7xyext;
							struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v7xyNonCriticalExtensions__nonCriticalExtensions {
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *nonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v7xyNonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v590NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *v4b0NonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *laterNonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct UECapabilityEnquiry__later_than_r3 {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct UECapabilityEnquiry__later_than_r3__criticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} later_than_r3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UECapabilityEnquiry_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UECapabilityEnquiry;
extern asn_CHOICE_specifics_t asn_SPC_UECapabilityEnquiry_specs_1;
extern asn_TYPE_member_t asn_MBR_UECapabilityEnquiry_1[2];
extern asn_per_constraints_t asn_PER_type_UECapabilityEnquiry_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UECapabilityEnquiry_H_ */
#include <asn_internal.h>