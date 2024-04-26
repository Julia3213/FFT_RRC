/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RLC_Capability_H_
#define	_RLC_Capability_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TotalRLC-AM-BufferSize.h"
#include "MaximumRLC-WindowSize.h"
#include "MaximumAM-EntityNumberRLC-Cap.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RLC-Capability */
typedef struct RLC_Capability {
	TotalRLC_AM_BufferSize_t	 totalRLC_AM_BufferSize;
	MaximumRLC_WindowSize_t	 maximumRLC_WindowSize;
	MaximumAM_EntityNumberRLC_Cap_t	 maximumAM_EntityNumber;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RLC_Capability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RLC_Capability;
extern asn_SEQUENCE_specifics_t asn_SPC_RLC_Capability_specs_1;
extern asn_TYPE_member_t asn_MBR_RLC_Capability_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _RLC_Capability_H_ */
#include <asn_internal.h>