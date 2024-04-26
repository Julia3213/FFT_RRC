/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_EDCH_Information_r6_H_
#define	_UL_EDCH_Information_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_EDCH_Information_r6__mac_es_e_resetIndicator {
	UL_EDCH_Information_r6__mac_es_e_resetIndicator_true	= 0
} e_UL_EDCH_Information_r6__mac_es_e_resetIndicator;

/* Forward declarations */
struct E_DPCCH_Info;
struct E_DPDCH_Info;
struct E_DPDCH_SchedulingTransmConfiguration;

/* UL-EDCH-Information-r6 */
typedef struct UL_EDCH_Information_r6 {
	long	*mac_es_e_resetIndicator	/* OPTIONAL */;
	struct E_DPCCH_Info	*e_DPCCH_Info	/* OPTIONAL */;
	struct E_DPDCH_Info	*e_DPDCH_Info	/* OPTIONAL */;
	struct E_DPDCH_SchedulingTransmConfiguration	*schedulingTransmConfiguration	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_EDCH_Information_r6_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_mac_es_e_resetIndicator_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_UL_EDCH_Information_r6;
extern asn_SEQUENCE_specifics_t asn_SPC_UL_EDCH_Information_r6_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_EDCH_Information_r6_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _UL_EDCH_Information_r6_H_ */
#include <asn_internal.h>