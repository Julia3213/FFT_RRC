/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_NewIntraFreqCell_H_
#define	_NewIntraFreqCell_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IntraFreqCellID.h"
#include "CellInfo.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NewIntraFreqCell */
typedef struct NewIntraFreqCell {
	IntraFreqCellID_t	*intraFreqCellID	/* OPTIONAL */;
	CellInfo_t	 cellInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NewIntraFreqCell_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NewIntraFreqCell;
extern asn_SEQUENCE_specifics_t asn_SPC_NewIntraFreqCell_specs_1;
extern asn_TYPE_member_t asn_MBR_NewIntraFreqCell_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _NewIntraFreqCell_H_ */
#include <asn_internal.h>