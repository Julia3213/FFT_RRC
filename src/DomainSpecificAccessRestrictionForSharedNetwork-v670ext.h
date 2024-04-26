/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DomainSpecificAccessRestrictionForSharedNetwork_v670ext_H_
#define	_DomainSpecificAccessRestrictionForSharedNetwork_v670ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DomainSpecificAccessRestrictionList-v670ext.h"
#include "DomainSpecificAccessRestrictionParam-v670ext.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DomainSpecificAccessRestrictionForSharedNetwork_v670ext_PR {
	DomainSpecificAccessRestrictionForSharedNetwork_v670ext_PR_NOTHING,	/* No components present */
	DomainSpecificAccessRestrictionForSharedNetwork_v670ext_PR_domainSpecificAccessRestictionList,
	DomainSpecificAccessRestrictionForSharedNetwork_v670ext_PR_domainSpecificAccessRestictionParametersForAll
} DomainSpecificAccessRestrictionForSharedNetwork_v670ext_PR;

/* DomainSpecificAccessRestrictionForSharedNetwork-v670ext */
typedef struct DomainSpecificAccessRestrictionForSharedNetwork_v670ext {
	DomainSpecificAccessRestrictionForSharedNetwork_v670ext_PR present;
	union DomainSpecificAccessRestrictionForSharedNetwork_v670ext_u {
		DomainSpecificAccessRestrictionList_v670ext_t	 domainSpecificAccessRestictionList;
		DomainSpecificAccessRestrictionParam_v670ext_t	 domainSpecificAccessRestictionParametersForAll;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DomainSpecificAccessRestrictionForSharedNetwork_v670ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DomainSpecificAccessRestrictionForSharedNetwork_v670ext;
extern asn_CHOICE_specifics_t asn_SPC_DomainSpecificAccessRestrictionForSharedNetwork_v670ext_specs_1;
extern asn_TYPE_member_t asn_MBR_DomainSpecificAccessRestrictionForSharedNetwork_v670ext_1[2];
extern asn_per_constraints_t asn_PER_type_DomainSpecificAccessRestrictionForSharedNetwork_v670ext_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _DomainSpecificAccessRestrictionForSharedNetwork_v670ext_H_ */
#include <asn_internal.h>