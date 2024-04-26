/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MBMS_TrCHInformation_SIB5_H_
#define	_MBMS_TrCHInformation_SIB5_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_PTM_RBInformation_CList;
struct MBMS_MSCH_ConfigurationInfo_r6;

/* MBMS-TrCHInformation-SIB5 */
typedef struct MBMS_TrCHInformation_SIB5 {
	long	 transpCh_Identity;
	struct MBMS_PTM_RBInformation_CList	*rbInformation	/* OPTIONAL */;
	struct MBMS_MSCH_ConfigurationInfo_r6	*msch_ConfigurationInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_TrCHInformation_SIB5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_TrCHInformation_SIB5;
extern asn_SEQUENCE_specifics_t asn_SPC_MBMS_TrCHInformation_SIB5_specs_1;
extern asn_TYPE_member_t asn_MBR_MBMS_TrCHInformation_SIB5_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_TrCHInformation_SIB5_H_ */
#include <asn_internal.h>
