/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellToReport_H_
#define	_CellToReport_H_


#include <asn_application.h>

/* Including external dependencies */
#include "BSICReported.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CellToReport */
typedef struct CellToReport {
	BSICReported_t	 bsicReported;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellToReport_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellToReport;
extern asn_SEQUENCE_specifics_t asn_SPC_CellToReport_specs_1;
extern asn_TYPE_member_t asn_MBR_CellToReport_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _CellToReport_H_ */
#include <asn_internal.h>
