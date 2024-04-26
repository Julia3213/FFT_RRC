/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_SecurityCapability_H_
#define	_SecurityCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SecurityCapability__cipheringAlgorithmCap {
	SecurityCapability__cipheringAlgorithmCap_spare15	= 0,
	SecurityCapability__cipheringAlgorithmCap_spare14	= 1,
	SecurityCapability__cipheringAlgorithmCap_spare13	= 2,
	SecurityCapability__cipheringAlgorithmCap_spare12	= 3,
	SecurityCapability__cipheringAlgorithmCap_spare11	= 4,
	SecurityCapability__cipheringAlgorithmCap_spare10	= 5,
	SecurityCapability__cipheringAlgorithmCap_spare9	= 6,
	SecurityCapability__cipheringAlgorithmCap_spare8	= 7,
	SecurityCapability__cipheringAlgorithmCap_spare7	= 8,
	SecurityCapability__cipheringAlgorithmCap_spare6	= 9,
	SecurityCapability__cipheringAlgorithmCap_spare5	= 10,
	SecurityCapability__cipheringAlgorithmCap_spare4	= 11,
	SecurityCapability__cipheringAlgorithmCap_spare3	= 12,
	SecurityCapability__cipheringAlgorithmCap_spare2	= 13,
	SecurityCapability__cipheringAlgorithmCap_uea1	= 14,
	SecurityCapability__cipheringAlgorithmCap_uea0	= 15
} e_SecurityCapability__cipheringAlgorithmCap;
typedef enum SecurityCapability__integrityProtectionAlgorithmCap {
	SecurityCapability__integrityProtectionAlgorithmCap_spare15	= 0,
	SecurityCapability__integrityProtectionAlgorithmCap_spare14	= 1,
	SecurityCapability__integrityProtectionAlgorithmCap_spare13	= 2,
	SecurityCapability__integrityProtectionAlgorithmCap_spare12	= 3,
	SecurityCapability__integrityProtectionAlgorithmCap_spare11	= 4,
	SecurityCapability__integrityProtectionAlgorithmCap_spare10	= 5,
	SecurityCapability__integrityProtectionAlgorithmCap_spare9	= 6,
	SecurityCapability__integrityProtectionAlgorithmCap_spare8	= 7,
	SecurityCapability__integrityProtectionAlgorithmCap_spare7	= 8,
	SecurityCapability__integrityProtectionAlgorithmCap_spare6	= 9,
	SecurityCapability__integrityProtectionAlgorithmCap_spare5	= 10,
	SecurityCapability__integrityProtectionAlgorithmCap_spare4	= 11,
	SecurityCapability__integrityProtectionAlgorithmCap_spare3	= 12,
	SecurityCapability__integrityProtectionAlgorithmCap_spare2	= 13,
	SecurityCapability__integrityProtectionAlgorithmCap_uia1	= 14,
	SecurityCapability__integrityProtectionAlgorithmCap_spare0	= 15
} e_SecurityCapability__integrityProtectionAlgorithmCap;

/* SecurityCapability */
typedef struct SecurityCapability {
	BIT_STRING_t	 cipheringAlgorithmCap;
	BIT_STRING_t	 integrityProtectionAlgorithmCap;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecurityCapability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SecurityCapability;
extern asn_SEQUENCE_specifics_t asn_SPC_SecurityCapability_specs_1;
extern asn_TYPE_member_t asn_MBR_SecurityCapability_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _SecurityCapability_H_ */
#include <asn_internal.h>
