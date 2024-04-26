/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PRACH_SystemInformation_LCR_r4_H_
#define	_PRACH_SystemInformation_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PRACH-RACH-Info-LCR-r4.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TransportFormatSet_LCR;
struct PRACH_Partitioning_LCR_r4;

/* PRACH-SystemInformation-LCR-r4 */
typedef struct PRACH_SystemInformation_LCR_r4 {
	PRACH_RACH_Info_LCR_r4_t	 prach_RACH_Info_LCR;
	struct TransportFormatSet_LCR	*rach_TransportFormatSet_LCR	/* OPTIONAL */;
	struct PRACH_Partitioning_LCR_r4	*prach_Partitioning_LCR	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PRACH_SystemInformation_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PRACH_SystemInformation_LCR_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_PRACH_SystemInformation_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_PRACH_SystemInformation_LCR_r4_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _PRACH_SystemInformation_LCR_r4_H_ */
#include <asn_internal.h>
