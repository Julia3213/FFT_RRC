/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_TrCH_TypeId1_r5_H_
#define	_DL_TrCH_TypeId1_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TransportChannelIdentity.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_TrCH_TypeId1_r5_PR {
	DL_TrCH_TypeId1_r5_PR_NOTHING,	/* No components present */
	DL_TrCH_TypeId1_r5_PR_dch,
	DL_TrCH_TypeId1_r5_PR_dsch,
	DL_TrCH_TypeId1_r5_PR_hsdsch
} DL_TrCH_TypeId1_r5_PR;

/* DL-TrCH-TypeId1-r5 */
typedef struct DL_TrCH_TypeId1_r5 {
	DL_TrCH_TypeId1_r5_PR present;
	union DL_TrCH_TypeId1_r5_u {
		TransportChannelIdentity_t	 dch;
		TransportChannelIdentity_t	 dsch;
		NULL_t	 hsdsch;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_TrCH_TypeId1_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_TrCH_TypeId1_r5;
extern asn_CHOICE_specifics_t asn_SPC_DL_TrCH_TypeId1_r5_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_TrCH_TypeId1_r5_1[3];
extern asn_per_constraints_t asn_PER_type_DL_TrCH_TypeId1_r5_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_TrCH_TypeId1_r5_H_ */
#include <asn_internal.h>
