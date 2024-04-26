/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RRCConnectionSetup_v590ext_IEs_H_
#define	_RRCConnectionSetup_v590ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SystemSpecificCapUpdateReq-v590ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DL_TPC_PowerOffsetPerRL_List;

/* RRCConnectionSetup-v590ext-IEs */
typedef struct RRCConnectionSetup_v590ext_IEs {
	SystemSpecificCapUpdateReq_v590ext_t	*systemSpecificCapUpdateReq	/* OPTIONAL */;
	struct DL_TPC_PowerOffsetPerRL_List	*dl_TPC_PowerOffsetPerRL_List	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionSetup_v590ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetup_v590ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionSetup_v590ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_RRCConnectionSetup_v590ext_IEs_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RRCConnectionSetup_v590ext_IEs_H_ */
#include <asn_internal.h>
