/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterFreqReportingCriteria_r6_H_
#define	_InterFreqReportingCriteria_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct InterFreqEventList_r6;

/* InterFreqReportingCriteria-r6 */
typedef struct InterFreqReportingCriteria_r6 {
	struct InterFreqEventList_r6	*interFreqEventList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqReportingCriteria_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqReportingCriteria_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_InterFreqReportingCriteria_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_InterFreqReportingCriteria_r6_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _InterFreqReportingCriteria_r6_H_ */
#include <asn_internal.h>
