/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RB_COUNT_C_MSB_Information_H_
#define	_RB_COUNT_C_MSB_Information_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include "COUNT-C-MSB.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RB-COUNT-C-MSB-Information */
typedef struct RB_COUNT_C_MSB_Information {
	RB_Identity_t	 rb_Identity;
	COUNT_C_MSB_t	 count_C_MSB_UL;
	COUNT_C_MSB_t	 count_C_MSB_DL;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_COUNT_C_MSB_Information_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_COUNT_C_MSB_Information;
extern asn_SEQUENCE_specifics_t asn_SPC_RB_COUNT_C_MSB_Information_specs_1;
extern asn_TYPE_member_t asn_MBR_RB_COUNT_C_MSB_Information_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _RB_COUNT_C_MSB_Information_H_ */
#include <asn_internal.h>
