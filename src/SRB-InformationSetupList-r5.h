/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SRB_InformationSetupList_r5_H_
#define	_SRB_InformationSetupList_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SRB_InformationSetup_r5;

/* SRB-InformationSetupList-r5 */
typedef struct SRB_InformationSetupList_r5 {
	A_SEQUENCE_OF(struct SRB_InformationSetup_r5) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SRB_InformationSetupList_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SRB_InformationSetupList_r5;
extern asn_SET_OF_specifics_t asn_SPC_SRB_InformationSetupList_r5_specs_1;
extern asn_TYPE_member_t asn_MBR_SRB_InformationSetupList_r5_1[1];
extern asn_per_constraints_t asn_PER_type_SRB_InformationSetupList_r5_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _SRB_InformationSetupList_r5_H_ */
#include <asn_internal.h>
