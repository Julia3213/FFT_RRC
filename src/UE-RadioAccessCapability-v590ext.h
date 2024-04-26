/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_RadioAccessCapability_v590ext_H_
#define	_UE_RadioAccessCapability_v590ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DL-CapabilityWithSimultaneousHS-DSCHConfig.h"
#include "PDCP-Capability-r5-ext.h"
#include "RLC-Capability-r5-ext.h"
#include "PhysicalChannelCapability-hspdsch-r5.h"
#include "MultiModeRAT-Capability-v590ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-RadioAccessCapability-v590ext */
typedef struct UE_RadioAccessCapability_v590ext {
	DL_CapabilityWithSimultaneousHS_DSCHConfig_t	*dl_CapabilityWithSimultaneousHS_DSCHConfig	/* OPTIONAL */;
	PDCP_Capability_r5_ext_t	 pdcp_Capability_r5_ext;
	RLC_Capability_r5_ext_t	 rlc_Capability_r5_ext;
	PhysicalChannelCapability_hspdsch_r5_t	 physicalChannelCapability;
	MultiModeRAT_Capability_v590ext_t	 multiModeRAT_Capability_v590ext;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_RadioAccessCapability_v590ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapability_v590ext;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapability_v590ext_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_RadioAccessCapability_v590ext_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_RadioAccessCapability_v590ext_H_ */
#include <asn_internal.h>
