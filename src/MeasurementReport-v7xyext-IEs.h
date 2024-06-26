/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementReport_v7xyext_IEs_H_
#define	_MeasurementReport_v7xyext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct VelocityEstimate;
struct UE_InternalMeasuredResults_r7;

/* MeasurementReport-v7xyext-IEs */
typedef struct MeasurementReport_v7xyext_IEs {
	struct VelocityEstimate	*velocityEstimate	/* OPTIONAL */;
	struct UE_InternalMeasuredResults_r7	*ue_InternalMeasuredResults	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementReport_v7xyext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementReport_v7xyext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementReport_v7xyext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementReport_v7xyext_IEs_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementReport_v7xyext_IEs_H_ */
#include <asn_internal.h>
