/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_E_DCH_AddReconf_MAC_d_FlowList_H_
#define	_E_DCH_AddReconf_MAC_d_FlowList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct E_DCH_AddReconf_MAC_d_Flow;

/* E-DCH-AddReconf-MAC-d-FlowList */
typedef struct E_DCH_AddReconf_MAC_d_FlowList {
	A_SEQUENCE_OF(struct E_DCH_AddReconf_MAC_d_Flow) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_DCH_AddReconf_MAC_d_FlowList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_DCH_AddReconf_MAC_d_FlowList;
extern asn_SET_OF_specifics_t asn_SPC_E_DCH_AddReconf_MAC_d_FlowList_specs_1;
extern asn_TYPE_member_t asn_MBR_E_DCH_AddReconf_MAC_d_FlowList_1[1];
extern asn_per_constraints_t asn_PER_type_E_DCH_AddReconf_MAC_d_FlowList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _E_DCH_AddReconf_MAC_d_FlowList_H_ */
#include <asn_internal.h>