/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TFCI_Range_H_
#define	_TFCI_Range_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "TFCS-InfoForDSCH.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TFCI-Range */
typedef struct TFCI_Range {
	long	 maxTFCIField2Value;
	TFCS_InfoForDSCH_t	 tfcs_InfoForDSCH;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TFCI_Range_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TFCI_Range;
extern asn_SEQUENCE_specifics_t asn_SPC_TFCI_Range_specs_1;
extern asn_TYPE_member_t asn_MBR_TFCI_Range_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _TFCI_Range_H_ */
#include <asn_internal.h>
