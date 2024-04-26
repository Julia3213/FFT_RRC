/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RadioBearerSetupComplete_H_
#define	_RadioBearerSetupComplete_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "UL-TimingAdvance.h"
#include "START-Value.h"
#include "ActivationTime.h"
#include <BIT_STRING.h>
#include "RadioBearerSetupComplete-v7xyext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntegrityProtActivationInfo;
struct RB_ActivationTimeInfoList;
struct UL_CounterSynchronisationInfo;

/* RadioBearerSetupComplete */
typedef struct RadioBearerSetupComplete {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	struct IntegrityProtActivationInfo	*ul_IntegProtActivationInfo	/* OPTIONAL */;
	UL_TimingAdvance_t	*ul_TimingAdvance	/* OPTIONAL */;
	START_Value_t	*start_Value	/* OPTIONAL */;
	ActivationTime_t	*count_C_ActivationTime	/* OPTIONAL */;
	struct RB_ActivationTimeInfoList	*dummy	/* OPTIONAL */;
	struct UL_CounterSynchronisationInfo	*ul_CounterSynchronisationInfo	/* OPTIONAL */;
	struct RadioBearerSetupComplete__laterNonCriticalExtensions {
		BIT_STRING_t	*radioBearerSetupComplete_r3_add_ext	/* OPTIONAL */;
		struct RadioBearerSetupComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions {
			RadioBearerSetupComplete_v7xyext_IEs_t	 radioBearerSetupComplete_v7xyext;
			struct RadioBearerSetupComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions__nonCriticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *nonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v7xyNonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadioBearerSetupComplete_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadioBearerSetupComplete;
extern asn_SEQUENCE_specifics_t asn_SPC_RadioBearerSetupComplete_specs_1;
extern asn_TYPE_member_t asn_MBR_RadioBearerSetupComplete_1[8];

#ifdef __cplusplus
}
#endif

#endif	/* _RadioBearerSetupComplete_H_ */
#include <asn_internal.h>
