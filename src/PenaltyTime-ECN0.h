/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PenaltyTime_ECN0_H_
#define	_PenaltyTime_ECN0_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "TemporaryOffsetList.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PenaltyTime_ECN0_PR {
	PenaltyTime_ECN0_PR_NOTHING,	/* No components present */
	PenaltyTime_ECN0_PR_notUsed,
	PenaltyTime_ECN0_PR_pt10,
	PenaltyTime_ECN0_PR_pt20,
	PenaltyTime_ECN0_PR_pt30,
	PenaltyTime_ECN0_PR_pt40,
	PenaltyTime_ECN0_PR_pt50,
	PenaltyTime_ECN0_PR_pt60
} PenaltyTime_ECN0_PR;

/* PenaltyTime-ECN0 */
typedef struct PenaltyTime_ECN0 {
	PenaltyTime_ECN0_PR present;
	union PenaltyTime_ECN0_u {
		NULL_t	 notUsed;
		TemporaryOffsetList_t	 pt10;
		TemporaryOffsetList_t	 pt20;
		TemporaryOffsetList_t	 pt30;
		TemporaryOffsetList_t	 pt40;
		TemporaryOffsetList_t	 pt50;
		TemporaryOffsetList_t	 pt60;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PenaltyTime_ECN0_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PenaltyTime_ECN0;
extern asn_CHOICE_specifics_t asn_SPC_PenaltyTime_ECN0_specs_1;
extern asn_TYPE_member_t asn_MBR_PenaltyTime_ECN0_1[7];
extern asn_per_constraints_t asn_PER_type_PenaltyTime_ECN0_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PenaltyTime_ECN0_H_ */
#include <asn_internal.h>
