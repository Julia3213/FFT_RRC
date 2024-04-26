/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementReportingMode_H_
#define	_MeasurementReportingMode_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TransferMode.h"
#include "PeriodicalOrEventTrigger.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MeasurementReportingMode */
typedef struct MeasurementReportingMode {
	TransferMode_t	 measurementReportTransferMode;
	PeriodicalOrEventTrigger_t	 periodicalOrEventTrigger;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementReportingMode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementReportingMode;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementReportingMode_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementReportingMode_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementReportingMode_H_ */
#include <asn_internal.h>
