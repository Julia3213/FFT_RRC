/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_ProtocolErrorInformation_H_
#define	_ProtocolErrorInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "ProtocolErrorCause.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ProtocolErrorInformation__diagnosticsType_PR {
	ProtocolErrorInformation__diagnosticsType_PR_NOTHING,	/* No components present */
	ProtocolErrorInformation__diagnosticsType_PR_type1,
	ProtocolErrorInformation__diagnosticsType_PR_spare
} ProtocolErrorInformation__diagnosticsType_PR;

/* ProtocolErrorInformation */
typedef struct ProtocolErrorInformation {
	struct ProtocolErrorInformation__diagnosticsType {
		ProtocolErrorInformation__diagnosticsType_PR present;
		union ProtocolErrorInformation__diagnosticsType_u {
			struct ProtocolErrorInformation__diagnosticsType__type1 {
				ProtocolErrorCause_t	 protocolErrorCause;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} type1;
			NULL_t	 spare;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} diagnosticsType;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolErrorInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ProtocolErrorInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_ProtocolErrorInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_ProtocolErrorInformation_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _ProtocolErrorInformation_H_ */
#include <asn_internal.h>