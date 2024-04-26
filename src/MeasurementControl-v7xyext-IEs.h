/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementControl_v7xyext_IEs_H_
#define	_MeasurementControl_v7xyext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-Positioning-Measurement-v7xyext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MeasurementControl-v7xyext-IEs */
typedef struct MeasurementControl_v7xyext_IEs {
	UE_Positioning_Measurement_v7xyext_t	 ue_Positioning_Measurement_v7xyext;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementControl_v7xyext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementControl_v7xyext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementControl_v7xyext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementControl_v7xyext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementControl_v7xyext_IEs_H_ */
#include <asn_internal.h>