/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_CCTrChListToRemove_H_
#define	_DL_CCTrChListToRemove_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TFCS-IdentityPlain.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DL-CCTrChListToRemove */
typedef struct DL_CCTrChListToRemove {
	A_SEQUENCE_OF(TFCS_IdentityPlain_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_CCTrChListToRemove_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_CCTrChListToRemove;
extern asn_SET_OF_specifics_t asn_SPC_DL_CCTrChListToRemove_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_CCTrChListToRemove_1[1];
extern asn_per_constraints_t asn_PER_type_DL_CCTrChListToRemove_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_CCTrChListToRemove_H_ */
#include <asn_internal.h>
