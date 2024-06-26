/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellUpdate_v7xyext_IEs_H_
#define	_CellUpdate_v7xyext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellUpdate_v7xyext_IEs__csCallType {
	CellUpdate_v7xyext_IEs__csCallType_speech	= 0,
	CellUpdate_v7xyext_IEs__csCallType_video	= 1,
	CellUpdate_v7xyext_IEs__csCallType_other	= 2,
	CellUpdate_v7xyext_IEs__csCallType_spare	= 3
} e_CellUpdate_v7xyext_IEs__csCallType;

/* CellUpdate-v7xyext-IEs */
typedef struct CellUpdate_v7xyext_IEs {
	long	*csCallType	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellUpdate_v7xyext_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_csCallType_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_CellUpdate_v7xyext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_CellUpdate_v7xyext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_CellUpdate_v7xyext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _CellUpdate_v7xyext_IEs_H_ */
#include <asn_internal.h>
