/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_InterFreqCellInfoList_H_
#define	_InterFreqCellInfoList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RemovedInterFreqCellList;
struct NewInterFreqCellList;
struct CellsForInterFreqMeasList;

/* InterFreqCellInfoList */
typedef struct InterFreqCellInfoList {
	struct RemovedInterFreqCellList	*removedInterFreqCellList	/* OPTIONAL */;
	struct NewInterFreqCellList	*newInterFreqCellList	/* OPTIONAL */;
	struct CellsForInterFreqMeasList	*cellsForInterFreqMeasList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqCellInfoList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqCellInfoList;
extern asn_SEQUENCE_specifics_t asn_SPC_InterFreqCellInfoList_specs_1;
extern asn_TYPE_member_t asn_MBR_InterFreqCellInfoList_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _InterFreqCellInfoList_H_ */
#include <asn_internal.h>
