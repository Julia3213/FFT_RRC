/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_BCCH_ModificationInfo_H_
#define	_BCCH_ModificationInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MIB-ValueTag.h"
#include "BCCH-ModificationTime.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BCCH-ModificationInfo */
typedef struct BCCH_ModificationInfo {
	MIB_ValueTag_t	 mib_ValueTag;
	BCCH_ModificationTime_t	*bcch_ModificationTime	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} BCCH_ModificationInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_BCCH_ModificationInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_BCCH_ModificationInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_BCCH_ModificationInfo_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _BCCH_ModificationInfo_H_ */
#include <asn_internal.h>
