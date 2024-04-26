/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PhysicalChannelCapability_edch_r6_H_
#define	_PhysicalChannelCapability_edch_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PhysicalChannelCapability_edch_r6__fdd_edch_PR {
	PhysicalChannelCapability_edch_r6__fdd_edch_PR_NOTHING,	/* No components present */
	PhysicalChannelCapability_edch_r6__fdd_edch_PR_supported,
	PhysicalChannelCapability_edch_r6__fdd_edch_PR_unsupported
} PhysicalChannelCapability_edch_r6__fdd_edch_PR;

/* PhysicalChannelCapability-edch-r6 */
typedef struct PhysicalChannelCapability_edch_r6 {
	struct PhysicalChannelCapability_edch_r6__fdd_edch {
		PhysicalChannelCapability_edch_r6__fdd_edch_PR present;
		union PhysicalChannelCapability_edch_r6__fdd_edch_u {
			struct PhysicalChannelCapability_edch_r6__fdd_edch__supported {
				long	 edch_PhysicalLayerCategory;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} supported;
			NULL_t	 unsupported;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} fdd_edch;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PhysicalChannelCapability_edch_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PhysicalChannelCapability_edch_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_PhysicalChannelCapability_edch_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_PhysicalChannelCapability_edch_r6_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _PhysicalChannelCapability_edch_r6_H_ */
#include <asn_internal.h>
