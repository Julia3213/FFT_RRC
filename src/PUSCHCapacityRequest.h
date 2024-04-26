/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PUSCHCapacityRequest_H_
#define	_PUSCHCapacityRequest_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DSCH-RNTI.h"
#include "PrimaryCCPCH-RSCP.h"
#include "ProtocolErrorIndicatorWithMoreInfo.h"
#include "PDSCH-Identity.h"
#include "PUSCH-Identity.h"
#include <constr_CHOICE.h>
#include <BIT_STRING.h>
#include "PUSCHCapacityRequest-v590ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PUSCHCapacityRequest__allocationConfirmation_PR {
	PUSCHCapacityRequest__allocationConfirmation_PR_NOTHING,	/* No components present */
	PUSCHCapacityRequest__allocationConfirmation_PR_pdschConfirmation,
	PUSCHCapacityRequest__allocationConfirmation_PR_puschConfirmation
} PUSCHCapacityRequest__allocationConfirmation_PR;

/* Forward declarations */
struct TrafficVolumeMeasuredResultsList;
struct TimeslotListWithISCP;

/* PUSCHCapacityRequest */
typedef struct PUSCHCapacityRequest {
	DSCH_RNTI_t	*dsch_RNTI	/* OPTIONAL */;
	struct TrafficVolumeMeasuredResultsList	*trafficVolume	/* OPTIONAL */;
	struct TimeslotListWithISCP	*timeslotListWithISCP	/* OPTIONAL */;
	PrimaryCCPCH_RSCP_t	*primaryCCPCH_RSCP	/* OPTIONAL */;
	struct PUSCHCapacityRequest__allocationConfirmation {
		PUSCHCapacityRequest__allocationConfirmation_PR present;
		union PUSCHCapacityRequest__allocationConfirmation_u {
			PDSCH_Identity_t	 pdschConfirmation;
			PUSCH_Identity_t	 puschConfirmation;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *allocationConfirmation;
	ProtocolErrorIndicatorWithMoreInfo_t	 protocolErrorIndicator;
	struct PUSCHCapacityRequest__laterNonCriticalExtensions {
		BIT_STRING_t	*puschCapacityRequest_r3_add_ext	/* OPTIONAL */;
		struct PUSCHCapacityRequest__laterNonCriticalExtensions__v590NonCriticalExtensions {
			PUSCHCapacityRequest_v590ext_t	 puschCapacityRequest_v590ext;
			struct PUSCHCapacityRequest__laterNonCriticalExtensions__v590NonCriticalExtensions__nonCriticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *nonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v590NonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PUSCHCapacityRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PUSCHCapacityRequest;
extern asn_SEQUENCE_specifics_t asn_SPC_PUSCHCapacityRequest_specs_1;
extern asn_TYPE_member_t asn_MBR_PUSCHCapacityRequest_1[7];

#ifdef __cplusplus
}
#endif

#endif	/* _PUSCHCapacityRequest_H_ */
#include <asn_internal.h>
