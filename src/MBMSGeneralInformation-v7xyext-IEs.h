/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MBMSGeneralInformation_v7xyext_IEs_H_
#define	_MBMSGeneralInformation_v7xyext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_MICHConfigurationInfo_r7;

/* MBMSGeneralInformation-v7xyext-IEs */
typedef struct MBMSGeneralInformation_v7xyext_IEs {
	struct MBMS_MICHConfigurationInfo_r7	*mbmsMICHConfiguration_v7xyext	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMSGeneralInformation_v7xyext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMSGeneralInformation_v7xyext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_MBMSGeneralInformation_v7xyext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_MBMSGeneralInformation_v7xyext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _MBMSGeneralInformation_v7xyext_IEs_H_ */
#include <asn_internal.h>
