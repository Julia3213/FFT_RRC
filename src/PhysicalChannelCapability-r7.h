/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PhysicalChannelCapability_r7_H_
#define	_PhysicalChannelCapability_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DL-PhysChCapabilityFDD.h"
#include "UL-PhysChCapabilityFDD.h"
#include <constr_SEQUENCE.h>
#include "DL-PhysChCapabilityTDD.h"
#include "UL-PhysChCapabilityTDD.h"
#include "DL-PhysChCapabilityTDD-768.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PhysicalChannelCapability-r7 */
typedef struct PhysicalChannelCapability_r7 {
	struct PhysicalChannelCapability_r7__fddPhysChCapability {
		DL_PhysChCapabilityFDD_t	 downlinkPhysChCapability;
		UL_PhysChCapabilityFDD_t	 uplinkPhysChCapability;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *fddPhysChCapability;
	struct PhysicalChannelCapability_r7__tddPhysChCapability {
		DL_PhysChCapabilityTDD_t	 downlinkPhysChCapability;
		UL_PhysChCapabilityTDD_t	 uplinkPhysChCapability;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *tddPhysChCapability;
	struct PhysicalChannelCapability_r7__tddPhysChCapability_768 {
		DL_PhysChCapabilityTDD_768_t	 downlinkPhysChCapability;
		UL_PhysChCapabilityTDD_t	 uplinkPhysChCapability;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tddPhysChCapability_768;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PhysicalChannelCapability_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PhysicalChannelCapability_r7;
extern asn_SEQUENCE_specifics_t asn_SPC_PhysicalChannelCapability_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_PhysicalChannelCapability_r7_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _PhysicalChannelCapability_r7_H_ */
#include <asn_internal.h>
