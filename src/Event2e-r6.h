/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_Event2e_r6_H_
#define	_Event2e_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "HysteresisInterFreq.h"
#include "TimeToTrigger.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ReportingCellStatus;
struct NonUsedFreqParameterList_r6;

/* Event2e-r6 */
typedef struct Event2e_r6 {
	HysteresisInterFreq_t	 hysteresis;
	TimeToTrigger_t	 timeToTrigger;
	struct ReportingCellStatus	*reportingCellStatus	/* OPTIONAL */;
	struct NonUsedFreqParameterList_r6	*nonUsedFreqParameterList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Event2e_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Event2e_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_Event2e_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_Event2e_r6_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _Event2e_r6_H_ */
#include <asn_internal.h>
