/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PDCP_Capability_r5_ext_H_
#define	_PDCP_Capability_r5_ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include "MaxHcContextSpace-r5-ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PDCP-Capability-r5-ext */
typedef struct PDCP_Capability_r5_ext {
	BOOLEAN_t	 supportForRfc3095ContextRelocation;
	MaxHcContextSpace_r5_ext_t	*maxHcContextSpace	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDCP_Capability_r5_ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDCP_Capability_r5_ext;
extern asn_SEQUENCE_specifics_t asn_SPC_PDCP_Capability_r5_ext_specs_1;
extern asn_TYPE_member_t asn_MBR_PDCP_Capability_r5_ext_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _PDCP_Capability_r5_ext_H_ */
#include <asn_internal.h>
