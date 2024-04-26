/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_StoredTGP_Sequence_H_
#define	_StoredTGP_Sequence_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TGPSI.h"
#include <NULL.h>
#include "TGCFN.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum StoredTGP_Sequence__current_tgps_Status_PR {
	StoredTGP_Sequence__current_tgps_Status_PR_NOTHING,	/* No components present */
	StoredTGP_Sequence__current_tgps_Status_PR_active,
	StoredTGP_Sequence__current_tgps_Status_PR_inactive
} StoredTGP_Sequence__current_tgps_Status_PR;

/* Forward declarations */
struct TGPS_ConfigurationParams;

/* StoredTGP-Sequence */
typedef struct StoredTGP_Sequence {
	TGPSI_t	 tgpsi;
	struct StoredTGP_Sequence__current_tgps_Status {
		StoredTGP_Sequence__current_tgps_Status_PR present;
		union StoredTGP_Sequence__current_tgps_Status_u {
			struct StoredTGP_Sequence__current_tgps_Status__active {
				TGCFN_t	 tgcfn;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} active;
			NULL_t	 inactive;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} current_tgps_Status;
	struct TGPS_ConfigurationParams	*tgps_ConfigurationParams	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} StoredTGP_Sequence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_StoredTGP_Sequence;
extern asn_SEQUENCE_specifics_t asn_SPC_StoredTGP_Sequence_specs_1;
extern asn_TYPE_member_t asn_MBR_StoredTGP_Sequence_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _StoredTGP_Sequence_H_ */
#include <asn_internal.h>
