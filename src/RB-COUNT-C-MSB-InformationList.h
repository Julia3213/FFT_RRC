/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RB_COUNT_C_MSB_InformationList_H_
#define	_RB_COUNT_C_MSB_InformationList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RB_COUNT_C_MSB_Information;

/* RB-COUNT-C-MSB-InformationList */
typedef struct RB_COUNT_C_MSB_InformationList {
	A_SEQUENCE_OF(struct RB_COUNT_C_MSB_Information) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_COUNT_C_MSB_InformationList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_COUNT_C_MSB_InformationList;
extern asn_SET_OF_specifics_t asn_SPC_RB_COUNT_C_MSB_InformationList_specs_1;
extern asn_TYPE_member_t asn_MBR_RB_COUNT_C_MSB_InformationList_1[1];
extern asn_per_constraints_t asn_PER_type_RB_COUNT_C_MSB_InformationList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RB_COUNT_C_MSB_InformationList_H_ */
#include <asn_internal.h>
