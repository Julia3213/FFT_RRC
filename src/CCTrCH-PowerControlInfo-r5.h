/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CCTrCH_PowerControlInfo_r5_H_
#define	_CCTrCH_PowerControlInfo_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UL-DPCH-PowerControlInfo-r5.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TFCS_Identity;

/* CCTrCH-PowerControlInfo-r5 */
typedef struct CCTrCH_PowerControlInfo_r5 {
	struct TFCS_Identity	*tfcs_Identity	/* OPTIONAL */;
	UL_DPCH_PowerControlInfo_r5_t	 ul_DPCH_PowerControlInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CCTrCH_PowerControlInfo_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CCTrCH_PowerControlInfo_r5;
extern asn_SEQUENCE_specifics_t asn_SPC_CCTrCH_PowerControlInfo_r5_specs_1;
extern asn_TYPE_member_t asn_MBR_CCTrCH_PowerControlInfo_r5_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _CCTrCH_PowerControlInfo_r5_H_ */
#include <asn_internal.h>