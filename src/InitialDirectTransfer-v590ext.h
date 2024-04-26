/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InitialDirectTransfer_v590ext_H_
#define	_InitialDirectTransfer_v590ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EstablishmentCause.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* InitialDirectTransfer-v590ext */
typedef struct InitialDirectTransfer_v590ext {
	EstablishmentCause_t	*establishmentCause	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InitialDirectTransfer_v590ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InitialDirectTransfer_v590ext;
extern asn_SEQUENCE_specifics_t asn_SPC_InitialDirectTransfer_v590ext_specs_1;
extern asn_TYPE_member_t asn_MBR_InitialDirectTransfer_v590ext_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _InitialDirectTransfer_v590ext_H_ */
#include <asn_internal.h>