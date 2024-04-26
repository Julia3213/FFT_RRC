/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementCommand_r6_H_
#define	_MeasurementCommand_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementType-r6.h"
#include <NULL.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MeasurementCommand_r6_PR {
	MeasurementCommand_r6_PR_NOTHING,	/* No components present */
	MeasurementCommand_r6_PR_setup,
	MeasurementCommand_r6_PR_modify,
	MeasurementCommand_r6_PR_release
} MeasurementCommand_r6_PR;

/* Forward declarations */
struct MeasurementType_r6;

/* MeasurementCommand-r6 */
typedef struct MeasurementCommand_r6 {
	MeasurementCommand_r6_PR present;
	union MeasurementCommand_r6_u {
		MeasurementType_r6_t	 setup;
		struct MeasurementCommand_r6__modify {
			struct MeasurementType_r6	*measurementType	/* OPTIONAL */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} modify;
		NULL_t	 release;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementCommand_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementCommand_r6;
extern asn_CHOICE_specifics_t asn_SPC_MeasurementCommand_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementCommand_r6_1[3];
extern asn_per_constraints_t asn_PER_type_MeasurementCommand_r6_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementCommand_r6_H_ */
#include <asn_internal.h>
