/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellSelectReselectInfoSIB_11_12_H_
#define	_CellSelectReselectInfoSIB_11_12_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Q-OffsetS-N.h"
#include "MaxAllowedUL-TX-Power.h"
#include "Q-QualMin.h"
#include "Q-RxlevMin.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR {
	CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR_NOTHING,	/* No components present */
	CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR_fdd,
	CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR_tdd,
	CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR_gsm
} CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR;

/* Forward declarations */
struct HCS_NeighbouringCellInformation_RSCP;

/* CellSelectReselectInfoSIB-11-12 */
typedef struct CellSelectReselectInfoSIB_11_12 {
	Q_OffsetS_N_t	 q_Offset1S_N	/* DEFAULT 0 */;
	Q_OffsetS_N_t	*q_Offset2S_N	/* OPTIONAL */;
	MaxAllowedUL_TX_Power_t	*maxAllowedUL_TX_Power	/* OPTIONAL */;
	struct HCS_NeighbouringCellInformation_RSCP	*hcs_NeighbouringCellInformation_RSCP	/* OPTIONAL */;
	struct CellSelectReselectInfoSIB_11_12__modeSpecificInfo {
		CellSelectReselectInfoSIB_11_12__modeSpecificInfo_PR present;
		union CellSelectReselectInfoSIB_11_12__modeSpecificInfo_u {
			struct CellSelectReselectInfoSIB_11_12__modeSpecificInfo__fdd {
				Q_QualMin_t	*q_QualMin	/* OPTIONAL */;
				Q_RxlevMin_t	*q_RxlevMin	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct CellSelectReselectInfoSIB_11_12__modeSpecificInfo__tdd {
				Q_RxlevMin_t	*q_RxlevMin	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
			struct CellSelectReselectInfoSIB_11_12__modeSpecificInfo__gsm {
				Q_RxlevMin_t	*q_RxlevMin	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} gsm;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellSelectReselectInfoSIB_11_12_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellSelectReselectInfoSIB_11_12;
extern asn_SEQUENCE_specifics_t asn_SPC_CellSelectReselectInfoSIB_11_12_specs_1;
extern asn_TYPE_member_t asn_MBR_CellSelectReselectInfoSIB_11_12_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _CellSelectReselectInfoSIB_11_12_H_ */
#include <asn_internal.h>
