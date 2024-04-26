/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IntraFreqCellInfoSI_List_HCS_ECN0_H_
#define	_IntraFreqCellInfoSI_List_HCS_ECN0_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NewIntraFreqCellSI-List-HCS-ECN0.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RemovedIntraFreqCellList;

/* IntraFreqCellInfoSI-List-HCS-ECN0 */
typedef struct IntraFreqCellInfoSI_List_HCS_ECN0 {
	struct RemovedIntraFreqCellList	*removedIntraFreqCellList	/* OPTIONAL */;
	NewIntraFreqCellSI_List_HCS_ECN0_t	 newIntraFreqCellList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqCellInfoSI_List_HCS_ECN0_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqCellInfoSI_List_HCS_ECN0;
extern asn_SEQUENCE_specifics_t asn_SPC_IntraFreqCellInfoSI_List_HCS_ECN0_specs_1;
extern asn_TYPE_member_t asn_MBR_IntraFreqCellInfoSI_List_HCS_ECN0_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _IntraFreqCellInfoSI_List_HCS_ECN0_H_ */
#include <asn_internal.h>
