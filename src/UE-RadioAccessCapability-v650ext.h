/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_RadioAccessCapability_v650ext_H_
#define	_UE_RadioAccessCapability_v650ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-RadioAccessCapabBandFDDList2.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UE_RadioAccessCapabBandFDDList_ext;

/* UE-RadioAccessCapability-v650ext */
typedef struct UE_RadioAccessCapability_v650ext {
	UE_RadioAccessCapabBandFDDList2_t	 ue_RadioAccessCapabBandFDDList2;
	struct UE_RadioAccessCapabBandFDDList_ext	*ue_RadioAccessCapabBandFDDList_ext	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_RadioAccessCapability_v650ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapability_v650ext;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapability_v650ext_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_RadioAccessCapability_v650ext_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_RadioAccessCapability_v650ext_H_ */
#include <asn_internal.h>
