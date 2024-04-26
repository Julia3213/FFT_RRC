/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterRATHandoverInfo_v590ext_IEs_H_
#define	_InterRATHandoverInfo_v590ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PredefinedConfigStatusListComp;
struct UE_RadioAccessCapabilityComp;

/* InterRATHandoverInfo-v590ext-IEs */
typedef struct InterRATHandoverInfo_v590ext_IEs {
	struct PredefinedConfigStatusListComp	*predefinedConfigStatusListComp	/* OPTIONAL */;
	struct UE_RadioAccessCapabilityComp	*ue_RadioAccessCapabilityComp	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRATHandoverInfo_v590ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRATHandoverInfo_v590ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_InterRATHandoverInfo_v590ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_InterRATHandoverInfo_v590ext_IEs_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _InterRATHandoverInfo_v590ext_IEs_H_ */
#include <asn_internal.h>
