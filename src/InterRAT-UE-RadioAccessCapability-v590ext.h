/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterRAT_UE_RadioAccessCapability_v590ext_H_
#define	_InterRAT_UE_RadioAccessCapability_v590ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GERANIu-RadioAccessCapability.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* InterRAT-UE-RadioAccessCapability-v590ext */
typedef struct InterRAT_UE_RadioAccessCapability_v590ext {
	GERANIu_RadioAccessCapability_t	 geranIu_RadioAccessCapability;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRAT_UE_RadioAccessCapability_v590ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRAT_UE_RadioAccessCapability_v590ext;
extern asn_SEQUENCE_specifics_t asn_SPC_InterRAT_UE_RadioAccessCapability_v590ext_specs_1;
extern asn_TYPE_member_t asn_MBR_InterRAT_UE_RadioAccessCapability_v590ext_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _InterRAT_UE_RadioAccessCapability_v590ext_H_ */
#include <asn_internal.h>
