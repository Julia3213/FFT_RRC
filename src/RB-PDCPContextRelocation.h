/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RB_PDCPContextRelocation_H_
#define	_RB_PDCPContextRelocation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RB-PDCPContextRelocation */
typedef struct RB_PDCPContextRelocation {
	RB_Identity_t	 rb_Identity;
	BOOLEAN_t	 dl_RFC3095_Context_Relocation;
	BOOLEAN_t	 ul_RFC3095_Context_Relocation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_PDCPContextRelocation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_PDCPContextRelocation;
extern asn_SEQUENCE_specifics_t asn_SPC_RB_PDCPContextRelocation_specs_1;
extern asn_TYPE_member_t asn_MBR_RB_PDCPContextRelocation_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _RB_PDCPContextRelocation_H_ */
#include <asn_internal.h>
