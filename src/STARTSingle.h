/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_STARTSingle_H_
#define	_STARTSingle_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CN-DomainIdentity.h"
#include "START-Value.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* STARTSingle */
typedef struct STARTSingle {
	CN_DomainIdentity_t	 cn_DomainIdentity;
	START_Value_t	 start_Value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} STARTSingle_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_STARTSingle;
extern asn_SEQUENCE_specifics_t asn_SPC_STARTSingle_specs_1;
extern asn_TYPE_member_t asn_MBR_STARTSingle_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _STARTSingle_H_ */
#include <asn_internal.h>