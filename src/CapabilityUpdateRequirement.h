/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CapabilityUpdateRequirement_H_
#define	_CapabilityUpdateRequirement_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SystemSpecificCapUpdateReqList;

/* CapabilityUpdateRequirement */
typedef struct CapabilityUpdateRequirement {
	BOOLEAN_t	 ue_RadioCapabilityFDDUpdateRequirement;
	BOOLEAN_t	 ue_RadioCapabilityTDDUpdateRequirement;
	struct SystemSpecificCapUpdateReqList	*systemSpecificCapUpdateReqList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CapabilityUpdateRequirement_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CapabilityUpdateRequirement;
extern asn_SEQUENCE_specifics_t asn_SPC_CapabilityUpdateRequirement_specs_1;
extern asn_TYPE_member_t asn_MBR_CapabilityUpdateRequirement_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _CapabilityUpdateRequirement_H_ */
#include <asn_internal.h>
