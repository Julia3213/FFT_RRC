/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_DPCH_PowerControlInfoPostTDD_LCR_r4_H_
#define	_UL_DPCH_PowerControlInfoPostTDD_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UL-TargetSIR.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UL-DPCH-PowerControlInfoPostTDD-LCR-r4 */
typedef struct UL_DPCH_PowerControlInfoPostTDD_LCR_r4 {
	UL_TargetSIR_t	 ul_TargetSIR;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_DPCH_PowerControlInfoPostTDD_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_DPCH_PowerControlInfoPostTDD_LCR_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_UL_DPCH_PowerControlInfoPostTDD_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_DPCH_PowerControlInfoPostTDD_LCR_r4_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _UL_DPCH_PowerControlInfoPostTDD_LCR_r4_H_ */
#include <asn_internal.h>
