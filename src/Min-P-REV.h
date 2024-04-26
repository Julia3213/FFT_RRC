/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_Min_P_REV_H_
#define	_Min_P_REV_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Min-P-REV */
typedef BIT_STRING_t	 Min_P_REV_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Min_P_REV_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Min_P_REV;
asn_struct_free_f Min_P_REV_free;
asn_struct_print_f Min_P_REV_print;
asn_constr_check_f Min_P_REV_constraint;
ber_type_decoder_f Min_P_REV_decode_ber;
der_type_encoder_f Min_P_REV_encode_der;
xer_type_decoder_f Min_P_REV_decode_xer;
xer_type_encoder_f Min_P_REV_encode_xer;
oer_type_decoder_f Min_P_REV_decode_oer;
oer_type_encoder_f Min_P_REV_encode_oer;
per_type_decoder_f Min_P_REV_decode_uper;
per_type_encoder_f Min_P_REV_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Min_P_REV_H_ */
#include <asn_internal.h>
