/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SysInfoType11_H_
#define	_SysInfoType11_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include "MeasurementControlSysInfo.h"
#include "SysInfoType11-v590ext-IEs.h"
#include "SysInfoType11-v690ext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct FACH_MeasurementOccasionInfo;
struct SysInfoType11_v4b0ext_IEs;

/* SysInfoType11 */
typedef struct SysInfoType11 {
	BOOLEAN_t	 sib12indicator;
	struct FACH_MeasurementOccasionInfo	*fach_MeasurementOccasionInfo	/* OPTIONAL */;
	MeasurementControlSysInfo_t	 measurementControlSysInfo;
	struct SysInfoType11__v4b0NonCriticalExtensions {
		struct SysInfoType11_v4b0ext_IEs	*sysInfoType11_v4b0ext	/* OPTIONAL */;
		struct SysInfoType11__v4b0NonCriticalExtensions__v590NonCriticalExtension {
			SysInfoType11_v590ext_IEs_t	 sysInfoType11_v590ext;
			struct SysInfoType11__v4b0NonCriticalExtensions__v590NonCriticalExtension__v690NonCriticalExtensions {
				SysInfoType11_v690ext_IEs_t	 sysInfoType11_v690ext;
				struct SysInfoType11__v4b0NonCriticalExtensions__v590NonCriticalExtension__v690NonCriticalExtensions__nonCriticalExtensions {
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *nonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v690NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v590NonCriticalExtension;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *v4b0NonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType11;

#ifdef __cplusplus
}
#endif

#endif	/* _SysInfoType11_H_ */
#include <asn_internal.h>
