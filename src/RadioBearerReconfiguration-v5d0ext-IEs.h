/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RadioBearerReconfiguration_v5d0ext_IEs_H_
#define	_RadioBearerReconfiguration_v5d0ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDCP-ROHC-TargetMode.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RadioBearerReconfiguration-v5d0ext-IEs */
typedef struct RadioBearerReconfiguration_v5d0ext_IEs {
	PDCP_ROHC_TargetMode_t	*pdcp_ROHC_TargetMode	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadioBearerReconfiguration_v5d0ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadioBearerReconfiguration_v5d0ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RadioBearerReconfiguration_v5d0ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_RadioBearerReconfiguration_v5d0ext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RadioBearerReconfiguration_v5d0ext_IEs_H_ */
#include <asn_internal.h>
