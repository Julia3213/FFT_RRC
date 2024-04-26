/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RB_InformationReconfig_r6_H_
#define	_RB_InformationReconfig_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include "PDCP-SN-Info.h"
#include "RB-StopContinue.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PDCP_InfoReconfig_r4;
struct RLC_Info_r6;
struct RB_MappingInfo_r6;

/* RB-InformationReconfig-r6 */
typedef struct RB_InformationReconfig_r6 {
	RB_Identity_t	 rb_Identity;
	struct PDCP_InfoReconfig_r4	*pdcp_Info	/* OPTIONAL */;
	PDCP_SN_Info_t	*pdcp_SN_Info	/* OPTIONAL */;
	struct RLC_Info_r6	*rlc_Info	/* OPTIONAL */;
	struct RB_MappingInfo_r6	*rb_MappingInfo	/* OPTIONAL */;
	RB_StopContinue_t	*rb_StopContinue	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_InformationReconfig_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_InformationReconfig_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_RB_InformationReconfig_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_RB_InformationReconfig_r6_1[6];

#ifdef __cplusplus
}
#endif

#endif	/* _RB_InformationReconfig_r6_H_ */
#include <asn_internal.h>
