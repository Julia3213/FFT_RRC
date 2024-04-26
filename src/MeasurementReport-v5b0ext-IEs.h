/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementReport_v5b0ext_IEs_H_
#define	_MeasurementReport_v5b0ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "InterRATCellInfoIndication.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MeasurementReport-v5b0ext-IEs */
typedef struct MeasurementReport_v5b0ext_IEs {
	InterRATCellInfoIndication_t	*interRATCellInfoIndication	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementReport_v5b0ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementReport_v5b0ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementReport_v5b0ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementReport_v5b0ext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementReport_v5b0ext_IEs_H_ */
#include <asn_internal.h>