/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_URAUpdate_H_
#define	_URAUpdate_H_


#include <asn_application.h>

/* Including external dependencies */
#include "U-RNTI.h"
#include "URA-UpdateCause.h"
#include "ProtocolErrorIndicatorWithMoreInfo.h"
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* URAUpdate */
typedef struct URAUpdate {
	U_RNTI_t	 u_RNTI;
	URA_UpdateCause_t	 ura_UpdateCause;
	ProtocolErrorIndicatorWithMoreInfo_t	 protocolErrorIndicator;
	struct URAUpdate__laterNonCriticalExtensions {
		BIT_STRING_t	*uraUpdate_r3_add_ext	/* OPTIONAL */;
		struct URAUpdate__laterNonCriticalExtensions__nonCriticalExtensions {
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *nonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} URAUpdate_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_URAUpdate;
extern asn_SEQUENCE_specifics_t asn_SPC_URAUpdate_specs_1;
extern asn_TYPE_member_t asn_MBR_URAUpdate_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _URAUpdate_H_ */
#include <asn_internal.h>
