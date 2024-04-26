/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellInfoSI_RSCP_LCR_r4_H_
#define	_CellInfoSI_RSCP_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CellIndividualOffset.h"
#include "PrimaryCCPCH-Info-LCR-r4.h"
#include "PrimaryCCPCH-TX-Power.h"
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ReferenceTimeDifferenceToCell;
struct TimeslotInfoList_LCR_r4;
struct CellSelectReselectInfoSIB_11_12_RSCP;

/* CellInfoSI-RSCP-LCR-r4 */
typedef struct CellInfoSI_RSCP_LCR_r4 {
	CellIndividualOffset_t	 cellIndividualOffset	/* DEFAULT 0 */;
	struct ReferenceTimeDifferenceToCell	*referenceTimeDifferenceToCell	/* OPTIONAL */;
	PrimaryCCPCH_Info_LCR_r4_t	 primaryCCPCH_Info;
	PrimaryCCPCH_TX_Power_t	*primaryCCPCH_TX_Power	/* OPTIONAL */;
	struct TimeslotInfoList_LCR_r4	*timeslotInfoList	/* OPTIONAL */;
	BOOLEAN_t	 readSFN_Indicator;
	struct CellSelectReselectInfoSIB_11_12_RSCP	*cellSelectionReselectionInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellInfoSI_RSCP_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellInfoSI_RSCP_LCR_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_CellInfoSI_RSCP_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_CellInfoSI_RSCP_LCR_r4_1[7];

#ifdef __cplusplus
}
#endif

#endif	/* _CellInfoSI_RSCP_LCR_r4_H_ */
#include <asn_internal.h>
