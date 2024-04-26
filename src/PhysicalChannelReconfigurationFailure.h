/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PhysicalChannelReconfigurationFailure_H_
#define	_PhysicalChannelReconfigurationFailure_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "FailureCauseWithProtErr.h"
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PhysicalChannelReconfigurationFailure */
typedef struct PhysicalChannelReconfigurationFailure {
	RRC_TransactionIdentifier_t	*rrc_TransactionIdentifier	/* OPTIONAL */;
	FailureCauseWithProtErr_t	 failureCause;
	struct PhysicalChannelReconfigurationFailure__laterNonCriticalExtensions {
		BIT_STRING_t	*physicalChannelReconfigurationFailure_r3_add_ext	/* OPTIONAL */;
		struct PhysicalChannelReconfigurationFailure__laterNonCriticalExtensions__nonCriticalExtensions {
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *nonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PhysicalChannelReconfigurationFailure_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PhysicalChannelReconfigurationFailure;
extern asn_SEQUENCE_specifics_t asn_SPC_PhysicalChannelReconfigurationFailure_specs_1;
extern asn_TYPE_member_t asn_MBR_PhysicalChannelReconfigurationFailure_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _PhysicalChannelReconfigurationFailure_H_ */
#include <asn_internal.h>