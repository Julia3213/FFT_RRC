/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CompressedModeMeasCapability_H_
#define	_CompressedModeMeasCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GSM_Measurements;

/* CompressedModeMeasCapability */
typedef struct CompressedModeMeasCapability {
	BOOLEAN_t	 fdd_Measurements;
	BOOLEAN_t	*tdd_Measurements	/* OPTIONAL */;
	struct GSM_Measurements	*gsm_Measurements	/* OPTIONAL */;
	BOOLEAN_t	*multiCarrierMeasurements	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CompressedModeMeasCapability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CompressedModeMeasCapability;
extern asn_SEQUENCE_specifics_t asn_SPC_CompressedModeMeasCapability_specs_1;
extern asn_TYPE_member_t asn_MBR_CompressedModeMeasCapability_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _CompressedModeMeasCapability_H_ */
#include <asn_internal.h>
