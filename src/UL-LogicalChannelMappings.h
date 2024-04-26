/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_LogicalChannelMappings_H_
#define	_UL_LogicalChannelMappings_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UL-LogicalChannelMapping.h"
#include "UL-LogicalChannelMappingList.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_LogicalChannelMappings_PR {
	UL_LogicalChannelMappings_PR_NOTHING,	/* No components present */
	UL_LogicalChannelMappings_PR_oneLogicalChannel,
	UL_LogicalChannelMappings_PR_twoLogicalChannels
} UL_LogicalChannelMappings_PR;

/* UL-LogicalChannelMappings */
typedef struct UL_LogicalChannelMappings {
	UL_LogicalChannelMappings_PR present;
	union UL_LogicalChannelMappings_u {
		UL_LogicalChannelMapping_t	 oneLogicalChannel;
		UL_LogicalChannelMappingList_t	 twoLogicalChannels;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_LogicalChannelMappings_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_LogicalChannelMappings;
extern asn_CHOICE_specifics_t asn_SPC_UL_LogicalChannelMappings_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_LogicalChannelMappings_1[2];
extern asn_per_constraints_t asn_PER_type_UL_LogicalChannelMappings_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_LogicalChannelMappings_H_ */
#include <asn_internal.h>
