/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_FrequencyInfo_H_
#define	_FrequencyInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "FrequencyInfoFDD.h"
#include "FrequencyInfoTDD.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum FrequencyInfo__modeSpecificInfo_PR {
	FrequencyInfo__modeSpecificInfo_PR_NOTHING,	/* No components present */
	FrequencyInfo__modeSpecificInfo_PR_fdd,
	FrequencyInfo__modeSpecificInfo_PR_tdd
} FrequencyInfo__modeSpecificInfo_PR;

/* FrequencyInfo */
typedef struct FrequencyInfo {
	struct FrequencyInfo__modeSpecificInfo {
		FrequencyInfo__modeSpecificInfo_PR present;
		union FrequencyInfo__modeSpecificInfo_u {
			FrequencyInfoFDD_t	 fdd;
			FrequencyInfoTDD_t	 tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} FrequencyInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_FrequencyInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_FrequencyInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_FrequencyInfo_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _FrequencyInfo_H_ */
#include <asn_internal.h>
