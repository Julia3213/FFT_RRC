/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RAB_Identity_H_
#define	_RAB_Identity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RAB_Identity_PR {
	RAB_Identity_PR_NOTHING,	/* No components present */
	RAB_Identity_PR_gsm_MAP_RAB_Identity,
	RAB_Identity_PR_ansi_41_RAB_Identity
} RAB_Identity_PR;

/* RAB-Identity */
typedef struct RAB_Identity {
	RAB_Identity_PR present;
	union RAB_Identity_u {
		BIT_STRING_t	 gsm_MAP_RAB_Identity;
		BIT_STRING_t	 ansi_41_RAB_Identity;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RAB_Identity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RAB_Identity;
extern asn_CHOICE_specifics_t asn_SPC_RAB_Identity_specs_1;
extern asn_TYPE_member_t asn_MBR_RAB_Identity_1[2];
extern asn_per_constraints_t asn_PER_type_RAB_Identity_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RAB_Identity_H_ */
#include <asn_internal.h>
