/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_NewIntraFreqCellSI_List_HCS_RSCP_H_
#define	_NewIntraFreqCellSI_List_HCS_RSCP_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NewIntraFreqCellSI_HCS_RSCP;

/* NewIntraFreqCellSI-List-HCS-RSCP */
typedef struct NewIntraFreqCellSI_List_HCS_RSCP {
	A_SEQUENCE_OF(struct NewIntraFreqCellSI_HCS_RSCP) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NewIntraFreqCellSI_List_HCS_RSCP_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NewIntraFreqCellSI_List_HCS_RSCP;
extern asn_SET_OF_specifics_t asn_SPC_NewIntraFreqCellSI_List_HCS_RSCP_specs_1;
extern asn_TYPE_member_t asn_MBR_NewIntraFreqCellSI_List_HCS_RSCP_1[1];
extern asn_per_constraints_t asn_PER_type_NewIntraFreqCellSI_List_HCS_RSCP_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _NewIntraFreqCellSI_List_HCS_RSCP_H_ */
#include <asn_internal.h>
