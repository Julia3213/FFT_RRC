/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementCommand_H_
#define	_MeasurementCommand_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementType.h"
#include <NULL.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MeasurementCommand_PR {
	MeasurementCommand_PR_NOTHING,	/* No components present */
	MeasurementCommand_PR_setup,
	MeasurementCommand_PR_modify,
	MeasurementCommand_PR_release
} MeasurementCommand_PR;

/* Forward declarations */
struct MeasurementType;

/* MeasurementCommand */
typedef struct MeasurementCommand {
	MeasurementCommand_PR present;
	union MeasurementCommand_u {
		MeasurementType_t	 setup;
		struct MeasurementCommand__modify {
			struct MeasurementType	*measurementType	/* OPTIONAL */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} modify;
		NULL_t	 release;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementCommand_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementCommand;
extern asn_CHOICE_specifics_t asn_SPC_MeasurementCommand_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementCommand_1[3];
extern asn_per_constraints_t asn_PER_type_MeasurementCommand_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementCommand_H_ */
#include <asn_internal.h>