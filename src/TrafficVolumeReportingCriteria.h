/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TrafficVolumeReportingCriteria_H_
#define	_TrafficVolumeReportingCriteria_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TransChCriteriaList;

/* TrafficVolumeReportingCriteria */
typedef struct TrafficVolumeReportingCriteria {
	struct TransChCriteriaList	*transChCriteriaList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TrafficVolumeReportingCriteria_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TrafficVolumeReportingCriteria;
extern asn_SEQUENCE_specifics_t asn_SPC_TrafficVolumeReportingCriteria_specs_1;
extern asn_TYPE_member_t asn_MBR_TrafficVolumeReportingCriteria_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _TrafficVolumeReportingCriteria_H_ */
#include <asn_internal.h>
