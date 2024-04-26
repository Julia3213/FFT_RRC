/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PLMNsOfInterFreqCellsList_H_
#define	_PLMNsOfInterFreqCellsList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PLMN_Identity;

/* Forward definitions */
typedef struct PLMNsOfInterFreqCellsList__Member {
	struct PLMN_Identity	*plmn_Identity	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PLMNsOfInterFreqCellsList__Member;

/* PLMNsOfInterFreqCellsList */
typedef struct PLMNsOfInterFreqCellsList {
	A_SEQUENCE_OF(PLMNsOfInterFreqCellsList__Member) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PLMNsOfInterFreqCellsList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PLMNsOfInterFreqCellsList;
extern asn_SET_OF_specifics_t asn_SPC_PLMNsOfInterFreqCellsList_specs_1;
extern asn_TYPE_member_t asn_MBR_PLMNsOfInterFreqCellsList_1[1];
extern asn_per_constraints_t asn_PER_type_PLMNsOfInterFreqCellsList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PLMNsOfInterFreqCellsList_H_ */
#include <asn_internal.h>
