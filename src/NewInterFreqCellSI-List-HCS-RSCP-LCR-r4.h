/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_H_
#define	_NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NewInterFreqCellSI_HCS_RSCP_LCR_r4;

/* NewInterFreqCellSI-List-HCS-RSCP-LCR-r4 */
typedef struct NewInterFreqCellSI_List_HCS_RSCP_LCR_r4 {
	A_SEQUENCE_OF(struct NewInterFreqCellSI_HCS_RSCP_LCR_r4) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NewInterFreqCellSI_List_HCS_RSCP_LCR_r4;
extern asn_SET_OF_specifics_t asn_SPC_NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_1[1];
extern asn_per_constraints_t asn_PER_type_NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _NewInterFreqCellSI_List_HCS_RSCP_LCR_r4_H_ */
#include <asn_internal.h>
