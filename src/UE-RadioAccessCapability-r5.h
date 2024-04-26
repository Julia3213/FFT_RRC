/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_RadioAccessCapability_r5_H_
#define	_UE_RadioAccessCapability_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AccessStratumReleaseIndicator.h"
#include "DL-CapabilityWithSimultaneousHS-DSCHConfig.h"
#include "PDCP-Capability-r5.h"
#include "RLC-Capability-r5.h"
#include "TransportChannelCapability.h"
#include "RF-Capability-r4.h"
#include "PhysicalChannelCapability-r5.h"
#include "UE-MultiModeRAT-Capability-r5.h"
#include "SecurityCapability.h"
#include "UE-Positioning-Capability-r4.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MeasurementCapability_r4;

/* UE-RadioAccessCapability-r5 */
typedef struct UE_RadioAccessCapability_r5 {
	AccessStratumReleaseIndicator_t	 accessStratumReleaseIndicator;
	DL_CapabilityWithSimultaneousHS_DSCHConfig_t	*dl_CapabilityWithSimultaneousHS_DSCHConfig	/* OPTIONAL */;
	PDCP_Capability_r5_t	 pdcp_Capability;
	RLC_Capability_r5_t	 rlc_Capability;
	TransportChannelCapability_t	 transportChannelCapability;
	RF_Capability_r4_t	 rf_Capability;
	PhysicalChannelCapability_r5_t	 physicalChannelCapability;
	UE_MultiModeRAT_Capability_r5_t	 ue_MultiModeRAT_Capability;
	SecurityCapability_t	 securityCapability;
	UE_Positioning_Capability_r4_t	 ue_positioning_Capability;
	struct MeasurementCapability_r4	*measurementCapability	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_RadioAccessCapability_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapability_r5;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapability_r5_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_RadioAccessCapability_r5_1[11];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_RadioAccessCapability_r5_H_ */
#include <asn_internal.h>
