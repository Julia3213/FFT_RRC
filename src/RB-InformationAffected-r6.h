/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RB_InformationAffected_r6_H_
#define	_RB_InformationAffected_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include "RB-MappingInfo-r6.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RB-InformationAffected-r6 */
typedef struct RB_InformationAffected_r6 {
	RB_Identity_t	 rb_Identity;
	RB_MappingInfo_r6_t	 rb_MappingInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_InformationAffected_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_InformationAffected_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_RB_InformationAffected_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_RB_InformationAffected_r6_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RB_InformationAffected_r6_H_ */
#include <asn_internal.h>