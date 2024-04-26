/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_RadioAccessCapability_v690ext_H_
#define	_UE_RadioAccessCapability_v690ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PhysicalChannelCapability-edch-r6.h"
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_RadioAccessCapability_v690ext__deviceType {
	UE_RadioAccessCapability_v690ext__deviceType_doesNotBenefitFromBatteryConsumptionOptimisation	= 0
} e_UE_RadioAccessCapability_v690ext__deviceType;

/* UE-RadioAccessCapability-v690ext */
typedef struct UE_RadioAccessCapability_v690ext {
	PhysicalChannelCapability_edch_r6_t	 physicalchannelcapability_edch;
	long	*deviceType	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_RadioAccessCapability_v690ext_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_deviceType_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapability_v690ext;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapability_v690ext_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_RadioAccessCapability_v690ext_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_RadioAccessCapability_v690ext_H_ */
#include <asn_internal.h>