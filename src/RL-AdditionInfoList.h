/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RL_AdditionInfoList_H_
#define	_RL_AdditionInfoList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PrimaryCPICH_Info;

/* RL-AdditionInfoList */
typedef struct RL_AdditionInfoList {
	A_SEQUENCE_OF(struct PrimaryCPICH_Info) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RL_AdditionInfoList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RL_AdditionInfoList;
extern asn_SET_OF_specifics_t asn_SPC_RL_AdditionInfoList_specs_1;
extern asn_TYPE_member_t asn_MBR_RL_AdditionInfoList_1[1];
extern asn_per_constraints_t asn_PER_type_RL_AdditionInfoList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RL_AdditionInfoList_H_ */
#include <asn_internal.h>