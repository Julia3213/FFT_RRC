/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SCCPCH_SystemInformation_LCR_r4_ext_H_
#define	_SCCPCH_SystemInformation_LCR_r4_ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SecondaryCCPCH-Info-LCR-r4-ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PICH_Info_LCR_r4;

/* SCCPCH-SystemInformation-LCR-r4-ext */
typedef struct SCCPCH_SystemInformation_LCR_r4_ext {
	SecondaryCCPCH_Info_LCR_r4_ext_t	 secondaryCCPCH_LCR_Extensions;
	struct PICH_Info_LCR_r4	*pich_Info	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SCCPCH_SystemInformation_LCR_r4_ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SCCPCH_SystemInformation_LCR_r4_ext;
extern asn_SEQUENCE_specifics_t asn_SPC_SCCPCH_SystemInformation_LCR_r4_ext_specs_1;
extern asn_TYPE_member_t asn_MBR_SCCPCH_SystemInformation_LCR_r4_ext_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _SCCPCH_SystemInformation_LCR_r4_ext_H_ */
#include <asn_internal.h>
