/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_OctetModeRLC_SizeInfoType1_H_
#define	_OctetModeRLC_SizeInfoType1_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OctetModeRLC_SizeInfoType1_PR {
	OctetModeRLC_SizeInfoType1_PR_NOTHING,	/* No components present */
	OctetModeRLC_SizeInfoType1_PR_sizeType1,
	OctetModeRLC_SizeInfoType1_PR_sizeType2,
	OctetModeRLC_SizeInfoType1_PR_sizeType3
} OctetModeRLC_SizeInfoType1_PR;

/* OctetModeRLC-SizeInfoType1 */
typedef struct OctetModeRLC_SizeInfoType1 {
	OctetModeRLC_SizeInfoType1_PR present;
	union OctetModeRLC_SizeInfoType1_u {
		long	 sizeType1;
		struct OctetModeRLC_SizeInfoType1__sizeType2 {
			long	 part1;
			long	*part2	/* OPTIONAL */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} sizeType2;
		struct OctetModeRLC_SizeInfoType1__sizeType3 {
			long	 part1;
			long	*part2	/* OPTIONAL */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} sizeType3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OctetModeRLC_SizeInfoType1_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OctetModeRLC_SizeInfoType1;
extern asn_CHOICE_specifics_t asn_SPC_OctetModeRLC_SizeInfoType1_specs_1;
extern asn_TYPE_member_t asn_MBR_OctetModeRLC_SizeInfoType1_1[3];
extern asn_per_constraints_t asn_PER_type_OctetModeRLC_SizeInfoType1_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _OctetModeRLC_SizeInfoType1_H_ */
#include <asn_internal.h>
