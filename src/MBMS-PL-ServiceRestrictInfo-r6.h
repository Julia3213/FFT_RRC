/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MBMS_PL_ServiceRestrictInfo_r6_H_
#define	_MBMS_PL_ServiceRestrictInfo_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MBMS_PL_ServiceRestrictInfo_r6 {
	MBMS_PL_ServiceRestrictInfo_r6_true	= 0
} e_MBMS_PL_ServiceRestrictInfo_r6;

/* MBMS-PL-ServiceRestrictInfo-r6 */
typedef long	 MBMS_PL_ServiceRestrictInfo_r6_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MBMS_PL_ServiceRestrictInfo_r6_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MBMS_PL_ServiceRestrictInfo_r6;
extern const asn_INTEGER_specifics_t asn_SPC_MBMS_PL_ServiceRestrictInfo_r6_specs_1;
asn_struct_free_f MBMS_PL_ServiceRestrictInfo_r6_free;
asn_struct_print_f MBMS_PL_ServiceRestrictInfo_r6_print;
asn_constr_check_f MBMS_PL_ServiceRestrictInfo_r6_constraint;
ber_type_decoder_f MBMS_PL_ServiceRestrictInfo_r6_decode_ber;
der_type_encoder_f MBMS_PL_ServiceRestrictInfo_r6_encode_der;
xer_type_decoder_f MBMS_PL_ServiceRestrictInfo_r6_decode_xer;
xer_type_encoder_f MBMS_PL_ServiceRestrictInfo_r6_encode_xer;
oer_type_decoder_f MBMS_PL_ServiceRestrictInfo_r6_decode_oer;
oer_type_encoder_f MBMS_PL_ServiceRestrictInfo_r6_encode_oer;
per_type_decoder_f MBMS_PL_ServiceRestrictInfo_r6_decode_uper;
per_type_encoder_f MBMS_PL_ServiceRestrictInfo_r6_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_PL_ServiceRestrictInfo_r6_H_ */
#include <asn_internal.h>