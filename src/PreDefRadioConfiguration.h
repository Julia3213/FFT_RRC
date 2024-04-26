/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PreDefRadioConfiguration_H_
#define	_PreDefRadioConfiguration_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PredefinedRB-Configuration.h"
#include "PreDefTransChConfiguration.h"
#include "PreDefPhyChConfiguration.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PreDefRadioConfiguration */
typedef struct PreDefRadioConfiguration {
	PredefinedRB_Configuration_t	 predefinedRB_Configuration;
	PreDefTransChConfiguration_t	 preDefTransChConfiguration;
	PreDefPhyChConfiguration_t	 preDefPhyChConfiguration;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PreDefRadioConfiguration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PreDefRadioConfiguration;
extern asn_SEQUENCE_specifics_t asn_SPC_PreDefRadioConfiguration_specs_1;
extern asn_TYPE_member_t asn_MBR_PreDefRadioConfiguration_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _PreDefRadioConfiguration_H_ */
#include <asn_internal.h>
