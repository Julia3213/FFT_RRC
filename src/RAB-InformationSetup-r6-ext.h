/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RAB_InformationSetup_r6_ext_H_
#define	_RAB_InformationSetup_r6_ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RAB-Info-r6-ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RAB-InformationSetup-r6-ext */
typedef struct RAB_InformationSetup_r6_ext {
	RAB_Info_r6_ext_t	 rab_Info_r6_ext;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RAB_InformationSetup_r6_ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RAB_InformationSetup_r6_ext;
extern asn_SEQUENCE_specifics_t asn_SPC_RAB_InformationSetup_r6_ext_specs_1;
extern asn_TYPE_member_t asn_MBR_RAB_InformationSetup_r6_ext_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RAB_InformationSetup_r6_ext_H_ */
#include <asn_internal.h>
