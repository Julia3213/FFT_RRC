/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_Measurement_H_
#define	_UE_Positioning_Measurement_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-Positioning-ReportingQuantity.h"
#include "UE-Positioning-ReportCriteria.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UE_Positioning_OTDOA_AssistanceData;
struct UE_Positioning_GPS_AssistanceData;

/* UE-Positioning-Measurement */
typedef struct UE_Positioning_Measurement {
	UE_Positioning_ReportingQuantity_t	 ue_positioning_ReportingQuantity;
	UE_Positioning_ReportCriteria_t	 reportCriteria;
	struct UE_Positioning_OTDOA_AssistanceData	*ue_positioning_OTDOA_AssistanceData	/* OPTIONAL */;
	struct UE_Positioning_GPS_AssistanceData	*ue_positioning_GPS_AssistanceData	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_Measurement_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_Measurement;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_Measurement_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_Positioning_Measurement_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_Measurement_H_ */
#include <asn_internal.h>