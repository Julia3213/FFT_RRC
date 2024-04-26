/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SysInfoType17_v590ext_IEs_H_
#define	_SysInfoType17_v590ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PUSCH_SysInfoList_HCR_r5;
struct PDSCH_SysInfoList_HCR_r5;

/* SysInfoType17-v590ext-IEs */
typedef struct SysInfoType17_v590ext_IEs {
	struct SysInfoType17_v590ext_IEs__hcr_r5_SpecificInfo {
		struct PUSCH_SysInfoList_HCR_r5	*pusch_SysInfoList	/* OPTIONAL */;
		struct PDSCH_SysInfoList_HCR_r5	*pdsch_SysInfoList	/* OPTIONAL */;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *hcr_r5_SpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType17_v590ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType17_v590ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_SysInfoType17_v590ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_SysInfoType17_v590ext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _SysInfoType17_v590ext_IEs_H_ */
#include <asn_internal.h>