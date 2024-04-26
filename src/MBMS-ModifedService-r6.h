/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MBMS_ModifedService_r6_H_
#define	_MBMS_ModifedService_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-TransmissionIdentity.h"
#include "MBMS-RequiredUEAction-Mod.h"
#include <NativeEnumerated.h>
#include <BOOLEAN.h>
#include "MBMS-PFLIndex.h"
#include "MBMS-PFLInfo.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MBMS_ModifedService_r6__mbms_PreferredFrequency_PR {
	MBMS_ModifedService_r6__mbms_PreferredFrequency_PR_NOTHING,	/* No components present */
	MBMS_ModifedService_r6__mbms_PreferredFrequency_PR_mcch,
	MBMS_ModifedService_r6__mbms_PreferredFrequency_PR_dcch
} MBMS_ModifedService_r6__mbms_PreferredFrequency_PR;
typedef enum MBMS_ModifedService_r6__mbms_DispersionIndicator {
	MBMS_ModifedService_r6__mbms_DispersionIndicator_true	= 0
} e_MBMS_ModifedService_r6__mbms_DispersionIndicator;

/* MBMS-ModifedService-r6 */
typedef struct MBMS_ModifedService_r6 {
	MBMS_TransmissionIdentity_t	 mbms_TransmissionIdentity;
	MBMS_RequiredUEAction_Mod_t	 mbms_RequiredUEAction;
	struct MBMS_ModifedService_r6__mbms_PreferredFrequency {
		MBMS_ModifedService_r6__mbms_PreferredFrequency_PR present;
		union MBMS_ModifedService_r6__mbms_PreferredFrequency_u {
			MBMS_PFLIndex_t	 mcch;
			MBMS_PFLInfo_t	 dcch;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *mbms_PreferredFrequency;
	long	*mbms_DispersionIndicator	/* OPTIONAL */;
	BOOLEAN_t	 continueMCCHReading;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_ModifedService_r6_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_mbms_DispersionIndicator_7;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_ModifedService_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_MBMS_ModifedService_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_MBMS_ModifedService_r6_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_ModifedService_r6_H_ */
#include <asn_internal.h>