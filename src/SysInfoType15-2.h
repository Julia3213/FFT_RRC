/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SysInfoType15_2_H_
#define	_SysInfoType15_2_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "SatID.h"
#include "EphemerisParameter.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SysInfoType15-2 */
typedef struct SysInfoType15_2 {
	long	 transmissionTOW;
	SatID_t	 satID;
	EphemerisParameter_t	 ephemerisParameter;
	struct SysInfoType15_2__nonCriticalExtensions {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType15_2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType15_2;

#ifdef __cplusplus
}
#endif

#endif	/* _SysInfoType15_2_H_ */
#include <asn_internal.h>
