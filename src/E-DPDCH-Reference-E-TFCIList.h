/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_E_DPDCH_Reference_E_TFCIList_H_
#define	_E_DPDCH_Reference_E_TFCIList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct E_DPDCH_Reference_E_TFCI;

/* E-DPDCH-Reference-E-TFCIList */
typedef struct E_DPDCH_Reference_E_TFCIList {
	A_SEQUENCE_OF(struct E_DPDCH_Reference_E_TFCI) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_DPDCH_Reference_E_TFCIList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_DPDCH_Reference_E_TFCIList;
extern asn_SET_OF_specifics_t asn_SPC_E_DPDCH_Reference_E_TFCIList_specs_1;
extern asn_TYPE_member_t asn_MBR_E_DPDCH_Reference_E_TFCIList_1[1];
extern asn_per_constraints_t asn_PER_type_E_DPDCH_Reference_E_TFCIList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _E_DPDCH_Reference_E_TFCIList_H_ */
#include <asn_internal.h>
