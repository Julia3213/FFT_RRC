/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementCapabilityExt2_H_
#define	_MeasurementCapabilityExt2_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CompressedModeMeasCapabFDDList2.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CompressedModeMeasCapabTDDList;
struct CompressedModeMeasCapabGSMList;
struct CompressedModeMeasCapabMC;

/* MeasurementCapabilityExt2 */
typedef struct MeasurementCapabilityExt2 {
	CompressedModeMeasCapabFDDList2_t	 compressedModeMeasCapabFDDList;
	struct CompressedModeMeasCapabTDDList	*compressedModeMeasCapabTDDList	/* OPTIONAL */;
	struct CompressedModeMeasCapabGSMList	*compressedModeMeasCapabGSMList	/* OPTIONAL */;
	struct CompressedModeMeasCapabMC	*compressedModeMeasCapabMC	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementCapabilityExt2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementCapabilityExt2;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementCapabilityExt2_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementCapabilityExt2_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementCapabilityExt2_H_ */
#include <asn_internal.h>