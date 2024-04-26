/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_E_RNTI_H_
#define	_E_RNTI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* E-RNTI */
typedef BIT_STRING_t	 E_RNTI_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_E_RNTI_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_E_RNTI;
asn_struct_free_f E_RNTI_free;
asn_struct_print_f E_RNTI_print;
asn_constr_check_f E_RNTI_constraint;
ber_type_decoder_f E_RNTI_decode_ber;
der_type_encoder_f E_RNTI_encode_der;
xer_type_decoder_f E_RNTI_decode_xer;
xer_type_encoder_f E_RNTI_encode_xer;
oer_type_decoder_f E_RNTI_decode_oer;
oer_type_encoder_f E_RNTI_encode_oer;
per_type_decoder_f E_RNTI_decode_uper;
per_type_encoder_f E_RNTI_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _E_RNTI_H_ */
#include <asn_internal.h>
