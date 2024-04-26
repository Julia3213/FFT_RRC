/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterRATHandoverInfo_v390ext_IEs_H_
#define	_InterRATHandoverInfo_v390ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DL-PhysChCapabilityFDD-v380ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UE_RadioAccessCapability_v380ext;

/* InterRATHandoverInfo-v390ext-IEs */
typedef struct InterRATHandoverInfo_v390ext_IEs {
	struct UE_RadioAccessCapability_v380ext	*ue_RadioAccessCapability_v380ext	/* OPTIONAL */;
	DL_PhysChCapabilityFDD_v380ext_t	 dl_PhysChCapabilityFDD_v380ext;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRATHandoverInfo_v390ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRATHandoverInfo_v390ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_InterRATHandoverInfo_v390ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_InterRATHandoverInfo_v390ext_IEs_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _InterRATHandoverInfo_v390ext_IEs_H_ */
#include <asn_internal.h>
