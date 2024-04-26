/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_NC_Mode_H_
#define	_NC_Mode_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NC-Mode */
typedef BIT_STRING_t	 NC_Mode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NC_Mode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NC_Mode;
asn_struct_free_f NC_Mode_free;
asn_struct_print_f NC_Mode_print;
asn_constr_check_f NC_Mode_constraint;
ber_type_decoder_f NC_Mode_decode_ber;
der_type_encoder_f NC_Mode_encode_der;
xer_type_decoder_f NC_Mode_decode_xer;
xer_type_encoder_f NC_Mode_encode_xer;
oer_type_decoder_f NC_Mode_decode_oer;
oer_type_encoder_f NC_Mode_encode_oer;
per_type_decoder_f NC_Mode_decode_uper;
per_type_encoder_f NC_Mode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _NC_Mode_H_ */
#include <asn_internal.h>
