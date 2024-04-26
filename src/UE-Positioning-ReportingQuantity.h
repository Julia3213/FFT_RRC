/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_ReportingQuantity_H_
#define	_UE_Positioning_ReportingQuantity_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-Positioning-MethodType.h"
#include "PositioningMethod.h"
#include "UE-Positioning-ResponseTime.h"
#include "UE-Positioning-Accuracy.h"
#include <BOOLEAN.h>
#include "EnvironmentCharacterisation.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-Positioning-ReportingQuantity */
typedef struct UE_Positioning_ReportingQuantity {
	UE_Positioning_MethodType_t	 methodType;
	PositioningMethod_t	 positioningMethod;
	UE_Positioning_ResponseTime_t	 dummy1;
	UE_Positioning_Accuracy_t	*horizontal_Accuracy	/* OPTIONAL */;
	BOOLEAN_t	 gps_TimingOfCellWanted;
	BOOLEAN_t	 dummy2;
	BOOLEAN_t	 additionalAssistanceDataRequest;
	EnvironmentCharacterisation_t	*environmentCharacterisation	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_ReportingQuantity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_ReportingQuantity;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_ReportingQuantity_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_Positioning_ReportingQuantity_1[8];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_ReportingQuantity_H_ */
#include <asn_internal.h>
