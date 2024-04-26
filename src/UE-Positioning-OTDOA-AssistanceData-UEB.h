/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_OTDOA_AssistanceData_UEB_H_
#define	_UE_Positioning_OTDOA_AssistanceData_UEB_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UE_Positioning_OTDOA_ReferenceCellInfo_UEB;
struct UE_Positioning_OTDOA_NeighbourCellList_UEB;

/* UE-Positioning-OTDOA-AssistanceData-UEB */
typedef struct UE_Positioning_OTDOA_AssistanceData_UEB {
	struct UE_Positioning_OTDOA_ReferenceCellInfo_UEB	*ue_positioning_OTDOA_ReferenceCellInfo_UEB	/* OPTIONAL */;
	struct UE_Positioning_OTDOA_NeighbourCellList_UEB	*ue_positioning_OTDOA_NeighbourCellList_UEB	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_OTDOA_AssistanceData_UEB_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_OTDOA_AssistanceData_UEB;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_OTDOA_AssistanceData_UEB_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_Positioning_OTDOA_AssistanceData_UEB_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_OTDOA_AssistanceData_UEB_H_ */
#include <asn_internal.h>