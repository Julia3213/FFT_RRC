/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MBMS_PTM_RBInformation_N_H_
#define	_MBMS_PTM_RBInformation_N_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-ShortTransmissionID.h"
#include "MBMS-LogicalChIdentity.h"
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MBMS-PTM-RBInformation-N */
typedef struct MBMS_PTM_RBInformation_N {
	MBMS_ShortTransmissionID_t	 shortTransmissionID;
	MBMS_LogicalChIdentity_t	 logicalChIdentity;
	BOOLEAN_t	 layer1_CombiningStatus;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_PTM_RBInformation_N_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_PTM_RBInformation_N;
extern asn_SEQUENCE_specifics_t asn_SPC_MBMS_PTM_RBInformation_N_specs_1;
extern asn_TYPE_member_t asn_MBR_MBMS_PTM_RBInformation_N_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_PTM_RBInformation_N_H_ */
#include <asn_internal.h>