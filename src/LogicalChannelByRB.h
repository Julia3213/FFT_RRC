/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_LogicalChannelByRB_H_
#define	_LogicalChannelByRB_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* LogicalChannelByRB */
typedef struct LogicalChannelByRB {
	RB_Identity_t	 rb_Identity;
	long	*logChOfRb	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LogicalChannelByRB_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LogicalChannelByRB;
extern asn_SEQUENCE_specifics_t asn_SPC_LogicalChannelByRB_specs_1;
extern asn_TYPE_member_t asn_MBR_LogicalChannelByRB_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _LogicalChannelByRB_H_ */
#include <asn_internal.h>
