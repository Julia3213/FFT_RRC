/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_GroupIdentityWithReleaseInformation_H_
#define	_GroupIdentityWithReleaseInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-ConnectionReleaseInformation.h"
#include "GroupReleaseInformation.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GroupIdentityWithReleaseInformation */
typedef struct GroupIdentityWithReleaseInformation {
	RRC_ConnectionReleaseInformation_t	 rrc_ConnectionReleaseInformation;
	GroupReleaseInformation_t	 groupReleaseInformation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GroupIdentityWithReleaseInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GroupIdentityWithReleaseInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_GroupIdentityWithReleaseInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_GroupIdentityWithReleaseInformation_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _GroupIdentityWithReleaseInformation_H_ */
#include <asn_internal.h>