/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_T_ADVinfo_H_
#define	_T_ADVinfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* T-ADVinfo */
typedef struct T_ADVinfo {
	long	 t_ADV;
	long	 sfn;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} T_ADVinfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_T_ADVinfo;
extern asn_SEQUENCE_specifics_t asn_SPC_T_ADVinfo_specs_1;
extern asn_TYPE_member_t asn_MBR_T_ADVinfo_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _T_ADVinfo_H_ */
#include <asn_internal.h>