/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellSelectReselectInfoSIB_3_4_H_
#define	_CellSelectReselectInfoSIB_3_4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Q-Hyst-S.h"
#include "T-Reselection-S.h"
#include "MaxAllowedUL-TX-Power.h"
#include <NULL.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>
#include "S-SearchQual.h"
#include "S-SearchRXLEV.h"
#include "Q-QualMin.h"
#include "Q-RxlevMin.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_PR {
	CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_PR_NOTHING,	/* No components present */
	CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_PR_cpich_Ec_N0,
	CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_PR_cpich_RSCP
} CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_PR;
typedef enum CellSelectReselectInfoSIB_3_4__modeSpecificInfo_PR {
	CellSelectReselectInfoSIB_3_4__modeSpecificInfo_PR_NOTHING,	/* No components present */
	CellSelectReselectInfoSIB_3_4__modeSpecificInfo_PR_fdd,
	CellSelectReselectInfoSIB_3_4__modeSpecificInfo_PR_tdd
} CellSelectReselectInfoSIB_3_4__modeSpecificInfo_PR;

/* Forward declarations */
struct MappingInfo;
struct HCS_ServingCellInformation;
struct RAT_FDD_InfoList;
struct RAT_TDD_InfoList;

/* CellSelectReselectInfoSIB-3-4 */
typedef struct CellSelectReselectInfoSIB_3_4 {
	struct MappingInfo	*mappingInfo	/* OPTIONAL */;
	struct CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure {
		CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_PR present;
		union CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure_u {
			struct CellSelectReselectInfoSIB_3_4__cellSelectQualityMeasure__cpich_Ec_N0 {
				Q_Hyst_S_t	*q_HYST_2_S	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} cpich_Ec_N0;
			NULL_t	 cpich_RSCP;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} cellSelectQualityMeasure;
	struct CellSelectReselectInfoSIB_3_4__modeSpecificInfo {
		CellSelectReselectInfoSIB_3_4__modeSpecificInfo_PR present;
		union CellSelectReselectInfoSIB_3_4__modeSpecificInfo_u {
			struct CellSelectReselectInfoSIB_3_4__modeSpecificInfo__fdd {
				S_SearchQual_t	*s_Intrasearch	/* OPTIONAL */;
				S_SearchQual_t	*s_Intersearch	/* OPTIONAL */;
				S_SearchRXLEV_t	*s_SearchHCS	/* OPTIONAL */;
				struct RAT_FDD_InfoList	*rat_List	/* OPTIONAL */;
				Q_QualMin_t	 q_QualMin;
				Q_RxlevMin_t	 q_RxlevMin;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct CellSelectReselectInfoSIB_3_4__modeSpecificInfo__tdd {
				S_SearchRXLEV_t	*s_Intrasearch	/* OPTIONAL */;
				S_SearchRXLEV_t	*s_Intersearch	/* OPTIONAL */;
				S_SearchRXLEV_t	*s_SearchHCS	/* OPTIONAL */;
				struct RAT_TDD_InfoList	*rat_List	/* OPTIONAL */;
				Q_RxlevMin_t	 q_RxlevMin;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	Q_Hyst_S_t	 q_Hyst_l_S;
	T_Reselection_S_t	 t_Reselection_S;
	struct HCS_ServingCellInformation	*hcs_ServingCellInformation	/* OPTIONAL */;
	MaxAllowedUL_TX_Power_t	 maxAllowedUL_TX_Power;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellSelectReselectInfoSIB_3_4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellSelectReselectInfoSIB_3_4;
extern asn_SEQUENCE_specifics_t asn_SPC_CellSelectReselectInfoSIB_3_4_specs_1;
extern asn_TYPE_member_t asn_MBR_CellSelectReselectInfoSIB_3_4_1[7];

#ifdef __cplusplus
}
#endif

#endif	/* _CellSelectReselectInfoSIB_3_4_H_ */
#include <asn_internal.h>
