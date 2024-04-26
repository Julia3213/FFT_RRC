/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TrafficVolumeMeasQuantity_H_
#define	_TrafficVolumeMeasQuantity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "TimeInterval.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TrafficVolumeMeasQuantity_PR {
	TrafficVolumeMeasQuantity_PR_NOTHING,	/* No components present */
	TrafficVolumeMeasQuantity_PR_rlc_BufferPayload,
	TrafficVolumeMeasQuantity_PR_averageRLC_BufferPayload,
	TrafficVolumeMeasQuantity_PR_varianceOfRLC_BufferPayload
} TrafficVolumeMeasQuantity_PR;

/* TrafficVolumeMeasQuantity */
typedef struct TrafficVolumeMeasQuantity {
	TrafficVolumeMeasQuantity_PR present;
	union TrafficVolumeMeasQuantity_u {
		NULL_t	 rlc_BufferPayload;
		TimeInterval_t	 averageRLC_BufferPayload;
		TimeInterval_t	 varianceOfRLC_BufferPayload;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TrafficVolumeMeasQuantity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TrafficVolumeMeasQuantity;
extern asn_CHOICE_specifics_t asn_SPC_TrafficVolumeMeasQuantity_specs_1;
extern asn_TYPE_member_t asn_MBR_TrafficVolumeMeasQuantity_1[3];
extern asn_per_constraints_t asn_PER_type_TrafficVolumeMeasQuantity_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _TrafficVolumeMeasQuantity_H_ */
#include <asn_internal.h>
