/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SRNC_RelocationInfo_v3h0ext_IEs_H_
#define	_SRNC_RelocationInfo_v3h0ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TPC_CombinationInfoList;

/* SRNC-RelocationInfo-v3h0ext-IEs */
typedef struct SRNC_RelocationInfo_v3h0ext_IEs {
	struct TPC_CombinationInfoList	*tpc_CombinationInfoList	/* OPTIONAL */;
	struct SRNC_RelocationInfo_v3h0ext_IEs__nonCriticalExtension {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtension;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SRNC_RelocationInfo_v3h0ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SRNC_RelocationInfo_v3h0ext_IEs;

#ifdef __cplusplus
}
#endif

#endif	/* _SRNC_RelocationInfo_v3h0ext_IEs_H_ */
#include <asn_internal.h>
