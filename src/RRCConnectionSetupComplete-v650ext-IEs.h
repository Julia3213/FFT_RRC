/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RRCConnectionSetupComplete_v650ext_IEs_H_
#define	_RRCConnectionSetupComplete_v650ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-RadioAccessCapability-v650ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RRCConnectionSetupComplete-v650ext-IEs */
typedef struct RRCConnectionSetupComplete_v650ext_IEs {
	UE_RadioAccessCapability_v650ext_t	 ue_RadioAccessCapability_v650ext;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionSetupComplete_v650ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetupComplete_v650ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionSetupComplete_v650ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_RRCConnectionSetupComplete_v650ext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RRCConnectionSetupComplete_v650ext_IEs_H_ */
#include <asn_internal.h>
