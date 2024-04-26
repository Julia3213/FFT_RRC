/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_LogicalChannelMappingList_H_
#define	_UL_LogicalChannelMappingList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UL_LogicalChannelMapping;

/* UL-LogicalChannelMappingList */
typedef struct UL_LogicalChannelMappingList {
	BOOLEAN_t	 rlc_LogicalChannelMappingIndicator;
	struct UL_LogicalChannelMappingList__ul_LogicalChannelMapping {
		A_SEQUENCE_OF(struct UL_LogicalChannelMapping) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} ul_LogicalChannelMapping;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_LogicalChannelMappingList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_LogicalChannelMappingList;
extern asn_SEQUENCE_specifics_t asn_SPC_UL_LogicalChannelMappingList_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_LogicalChannelMappingList_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UL_LogicalChannelMappingList_H_ */
#include <asn_internal.h>
