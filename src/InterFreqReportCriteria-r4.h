/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterFreqReportCriteria_r4_H_
#define	_InterFreqReportCriteria_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IntraFreqReportingCriteria-r4.h"
#include "InterFreqReportingCriteria.h"
#include "PeriodicalWithReportingCellStatus.h"
#include "ReportingCellStatusOpt.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterFreqReportCriteria_r4_PR {
	InterFreqReportCriteria_r4_PR_NOTHING,	/* No components present */
	InterFreqReportCriteria_r4_PR_intraFreqReportingCriteria,
	InterFreqReportCriteria_r4_PR_interFreqReportingCriteria,
	InterFreqReportCriteria_r4_PR_periodicalReportingCriteria,
	InterFreqReportCriteria_r4_PR_noReporting
} InterFreqReportCriteria_r4_PR;

/* InterFreqReportCriteria-r4 */
typedef struct InterFreqReportCriteria_r4 {
	InterFreqReportCriteria_r4_PR present;
	union InterFreqReportCriteria_r4_u {
		IntraFreqReportingCriteria_r4_t	 intraFreqReportingCriteria;
		InterFreqReportingCriteria_t	 interFreqReportingCriteria;
		PeriodicalWithReportingCellStatus_t	 periodicalReportingCriteria;
		ReportingCellStatusOpt_t	 noReporting;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqReportCriteria_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqReportCriteria_r4;
extern asn_CHOICE_specifics_t asn_SPC_InterFreqReportCriteria_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_InterFreqReportCriteria_r4_1[4];
extern asn_per_constraints_t asn_PER_type_InterFreqReportCriteria_r4_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _InterFreqReportCriteria_r4_H_ */
#include <asn_internal.h>