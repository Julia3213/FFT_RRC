/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SRB_SpecificIntegrityProtInfo_H_
#define	_SRB_SpecificIntegrityProtInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include "RRC-MessageSequenceNumber.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SRB-SpecificIntegrityProtInfo */
typedef struct SRB_SpecificIntegrityProtInfo {
	BIT_STRING_t	 ul_RRC_HFN;
	BIT_STRING_t	 dl_RRC_HFN;
	RRC_MessageSequenceNumber_t	 ul_RRC_SequenceNumber;
	RRC_MessageSequenceNumber_t	 dl_RRC_SequenceNumber;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SRB_SpecificIntegrityProtInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SRB_SpecificIntegrityProtInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_SRB_SpecificIntegrityProtInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_SRB_SpecificIntegrityProtInfo_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _SRB_SpecificIntegrityProtInfo_H_ */
#include <asn_internal.h>