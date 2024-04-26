/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PDCP_Info_r4_H_
#define	_PDCP_Info_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDCP-PDU-Header.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LosslessSRNS_RelocSupport;
struct HeaderCompressionInfoList_r4;

/* PDCP-Info-r4 */
typedef struct PDCP_Info_r4 {
	struct LosslessSRNS_RelocSupport	*losslessSRNS_RelocSupport	/* OPTIONAL */;
	PDCP_PDU_Header_t	 pdcp_PDU_Header;
	struct HeaderCompressionInfoList_r4	*headerCompressionInfoList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDCP_Info_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDCP_Info_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_PDCP_Info_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_PDCP_Info_r4_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _PDCP_Info_r4_H_ */
#include <asn_internal.h>