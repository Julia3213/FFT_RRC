/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_Measurement_v7xyext_H_
#define	_UE_Positioning_Measurement_v7xyext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-Positioning-ReportingQuantity-v7xyext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-Positioning-Measurement-v7xyext */
typedef struct UE_Positioning_Measurement_v7xyext {
	UE_Positioning_ReportingQuantity_v7xyext_t	 ue_positioning_ReportingQuantity;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_Measurement_v7xyext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_Measurement_v7xyext;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_Measurement_v7xyext_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_Positioning_Measurement_v7xyext_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_Measurement_v7xyext_H_ */
#include <asn_internal.h>