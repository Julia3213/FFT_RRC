/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_OngoingMeasRep_r4_H_
#define	_OngoingMeasRep_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity.h"
#include "MeasurementCommandWithType-r4.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MeasurementReportingMode;
struct AdditionalMeasurementID_List;

/* OngoingMeasRep-r4 */
typedef struct OngoingMeasRep_r4 {
	MeasurementIdentity_t	 measurementIdentity;
	MeasurementCommandWithType_r4_t	 measurementCommandWithType;
	struct MeasurementReportingMode	*measurementReportingMode	/* OPTIONAL */;
	struct AdditionalMeasurementID_List	*additionalMeasurementID_List	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OngoingMeasRep_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OngoingMeasRep_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_OngoingMeasRep_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_OngoingMeasRep_r4_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _OngoingMeasRep_r4_H_ */
#include <asn_internal.h>
