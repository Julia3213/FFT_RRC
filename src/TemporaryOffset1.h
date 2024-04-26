/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TemporaryOffset1_H_
#define	_TemporaryOffset1_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TemporaryOffset1 {
	TemporaryOffset1_to3	= 0,
	TemporaryOffset1_to6	= 1,
	TemporaryOffset1_to9	= 2,
	TemporaryOffset1_to12	= 3,
	TemporaryOffset1_to15	= 4,
	TemporaryOffset1_to18	= 5,
	TemporaryOffset1_to21	= 6,
	TemporaryOffset1_infinite	= 7
} e_TemporaryOffset1;

/* TemporaryOffset1 */
typedef long	 TemporaryOffset1_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TemporaryOffset1_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TemporaryOffset1;
extern const asn_INTEGER_specifics_t asn_SPC_TemporaryOffset1_specs_1;
asn_struct_free_f TemporaryOffset1_free;
asn_struct_print_f TemporaryOffset1_print;
asn_constr_check_f TemporaryOffset1_constraint;
ber_type_decoder_f TemporaryOffset1_decode_ber;
der_type_encoder_f TemporaryOffset1_encode_der;
xer_type_decoder_f TemporaryOffset1_decode_xer;
xer_type_encoder_f TemporaryOffset1_encode_xer;
oer_type_decoder_f TemporaryOffset1_decode_oer;
oer_type_encoder_f TemporaryOffset1_encode_oer;
per_type_decoder_f TemporaryOffset1_decode_uper;
per_type_encoder_f TemporaryOffset1_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TemporaryOffset1_H_ */
#include <asn_internal.h>
