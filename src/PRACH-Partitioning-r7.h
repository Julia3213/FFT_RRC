/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PRACH_Partitioning_r7_H_
#define	_PRACH_Partitioning_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PRACH_Partitioning_r7_PR {
	PRACH_Partitioning_r7_PR_NOTHING,	/* No components present */
	PRACH_Partitioning_r7_PR_fdd,
	PRACH_Partitioning_r7_PR_tdd
} PRACH_Partitioning_r7_PR;

/* Forward declarations */
struct ASCSetting_FDD;
struct ASCSetting_TDD_r7;

/* PRACH-Partitioning-r7 */
typedef struct PRACH_Partitioning_r7 {
	PRACH_Partitioning_r7_PR present;
	union PRACH_Partitioning_r7_u {
		struct PRACH_Partitioning_r7__fdd {
			A_SEQUENCE_OF(struct ASCSetting_FDD) list;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} fdd;
		struct PRACH_Partitioning_r7__tdd {
			A_SEQUENCE_OF(struct ASCSetting_TDD_r7) list;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} tdd;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PRACH_Partitioning_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PRACH_Partitioning_r7;
extern asn_CHOICE_specifics_t asn_SPC_PRACH_Partitioning_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_PRACH_Partitioning_r7_1[2];
extern asn_per_constraints_t asn_PER_type_PRACH_Partitioning_r7_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PRACH_Partitioning_r7_H_ */
#include <asn_internal.h>
