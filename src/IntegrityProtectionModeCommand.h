/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IntegrityProtectionModeCommand_H_
#define	_IntegrityProtectionModeCommand_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IntegrityProtInitNumber.h"
#include <constr_SEQUENCE.h>
#include "IntegrityProtActivationInfo.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IntegrityProtectionModeCommand_PR {
	IntegrityProtectionModeCommand_PR_NOTHING,	/* No components present */
	IntegrityProtectionModeCommand_PR_startIntegrityProtection,
	IntegrityProtectionModeCommand_PR_modify
} IntegrityProtectionModeCommand_PR;

/* IntegrityProtectionModeCommand */
typedef struct IntegrityProtectionModeCommand {
	IntegrityProtectionModeCommand_PR present;
	union IntegrityProtectionModeCommand_u {
		struct IntegrityProtectionModeCommand__startIntegrityProtection {
			IntegrityProtInitNumber_t	 integrityProtInitNumber;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} startIntegrityProtection;
		struct IntegrityProtectionModeCommand__modify {
			IntegrityProtActivationInfo_t	 dl_IntegrityProtActivationInfo;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} modify;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntegrityProtectionModeCommand_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntegrityProtectionModeCommand;
extern asn_CHOICE_specifics_t asn_SPC_IntegrityProtectionModeCommand_specs_1;
extern asn_TYPE_member_t asn_MBR_IntegrityProtectionModeCommand_1[2];
extern asn_per_constraints_t asn_PER_type_IntegrityProtectionModeCommand_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _IntegrityProtectionModeCommand_H_ */
#include <asn_internal.h>