/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SysInfoType14_H_
#define	_SysInfoType14_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IndividualTS-InterferenceList.h"
#include "ExpirationTimeFactor.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SysInfoType14 */
typedef struct SysInfoType14 {
	IndividualTS_InterferenceList_t	 individualTS_InterferenceList;
	ExpirationTimeFactor_t	*expirationTimeFactor	/* OPTIONAL */;
	struct SysInfoType14__nonCriticalExtensions {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType14_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType14;

#ifdef __cplusplus
}
#endif

#endif	/* _SysInfoType14_H_ */
#include <asn_internal.h>
