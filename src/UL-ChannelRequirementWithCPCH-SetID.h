/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_ChannelRequirementWithCPCH_SetID_H_
#define	_UL_ChannelRequirementWithCPCH_SetID_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UL-DPCH-Info.h"
#include "CPCH-SetInfo.h"
#include "CPCH-SetID.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_ChannelRequirementWithCPCH_SetID_PR {
	UL_ChannelRequirementWithCPCH_SetID_PR_NOTHING,	/* No components present */
	UL_ChannelRequirementWithCPCH_SetID_PR_ul_DPCH_Info,
	UL_ChannelRequirementWithCPCH_SetID_PR_dummy1,
	UL_ChannelRequirementWithCPCH_SetID_PR_dummy2
} UL_ChannelRequirementWithCPCH_SetID_PR;

/* UL-ChannelRequirementWithCPCH-SetID */
typedef struct UL_ChannelRequirementWithCPCH_SetID {
	UL_ChannelRequirementWithCPCH_SetID_PR present;
	union UL_ChannelRequirementWithCPCH_SetID_u {
		UL_DPCH_Info_t	 ul_DPCH_Info;
		CPCH_SetInfo_t	 dummy1;
		CPCH_SetID_t	 dummy2;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_ChannelRequirementWithCPCH_SetID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_ChannelRequirementWithCPCH_SetID;
extern asn_CHOICE_specifics_t asn_SPC_UL_ChannelRequirementWithCPCH_SetID_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_ChannelRequirementWithCPCH_SetID_1[3];
extern asn_per_constraints_t asn_PER_type_UL_ChannelRequirementWithCPCH_SetID_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_ChannelRequirementWithCPCH_SetID_H_ */
#include <asn_internal.h>
