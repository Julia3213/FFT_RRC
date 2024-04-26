/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_AllowedIndicator_H_
#define	_AllowedIndicator_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AllowedIndicator {
	AllowedIndicator_allowed	= 0,
	AllowedIndicator_notAllowed	= 1
} e_AllowedIndicator;

/* AllowedIndicator */
typedef long	 AllowedIndicator_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AllowedIndicator_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AllowedIndicator;
extern const asn_INTEGER_specifics_t asn_SPC_AllowedIndicator_specs_1;
asn_struct_free_f AllowedIndicator_free;
asn_struct_print_f AllowedIndicator_print;
asn_constr_check_f AllowedIndicator_constraint;
ber_type_decoder_f AllowedIndicator_decode_ber;
der_type_encoder_f AllowedIndicator_encode_der;
xer_type_decoder_f AllowedIndicator_decode_xer;
xer_type_encoder_f AllowedIndicator_encode_xer;
oer_type_decoder_f AllowedIndicator_decode_oer;
oer_type_encoder_f AllowedIndicator_encode_oer;
per_type_decoder_f AllowedIndicator_decode_uper;
per_type_encoder_f AllowedIndicator_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AllowedIndicator_H_ */
#include <asn_internal.h>