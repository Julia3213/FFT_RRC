/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SCCPCH_InfoForFACH_H_
#define	_SCCPCH_InfoForFACH_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SecondaryCCPCH-Info.h"
#include "TFCS.h"
#include "FACH-PCH-InformationList.h"
#include "SIB-ReferenceListFACH.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SCCPCH_InfoForFACH__modeSpecificInfo_PR {
	SCCPCH_InfoForFACH__modeSpecificInfo_PR_NOTHING,	/* No components present */
	SCCPCH_InfoForFACH__modeSpecificInfo_PR_fdd,
	SCCPCH_InfoForFACH__modeSpecificInfo_PR_tdd
} SCCPCH_InfoForFACH__modeSpecificInfo_PR;

/* SCCPCH-InfoForFACH */
typedef struct SCCPCH_InfoForFACH {
	SecondaryCCPCH_Info_t	 secondaryCCPCH_Info;
	TFCS_t	 tfcs;
	struct SCCPCH_InfoForFACH__modeSpecificInfo {
		SCCPCH_InfoForFACH__modeSpecificInfo_PR present;
		union SCCPCH_InfoForFACH__modeSpecificInfo_u {
			struct SCCPCH_InfoForFACH__modeSpecificInfo__fdd {
				FACH_PCH_InformationList_t	 fach_PCH_InformationList;
				SIB_ReferenceListFACH_t	 sib_ReferenceListFACH;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct SCCPCH_InfoForFACH__modeSpecificInfo__tdd {
				FACH_PCH_InformationList_t	 fach_PCH_InformationList;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SCCPCH_InfoForFACH_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SCCPCH_InfoForFACH;
extern asn_SEQUENCE_specifics_t asn_SPC_SCCPCH_InfoForFACH_specs_1;
extern asn_TYPE_member_t asn_MBR_SCCPCH_InfoForFACH_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _SCCPCH_InfoForFACH_H_ */
#include <asn_internal.h>
