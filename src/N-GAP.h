/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_N_GAP_H_
#define	_N_GAP_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum N_GAP {
	N_GAP_f2	= 0,
	N_GAP_f4	= 1,
	N_GAP_f8	= 2
} e_N_GAP;

/* N-GAP */
typedef long	 N_GAP_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_N_GAP_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_N_GAP;
extern const asn_INTEGER_specifics_t asn_SPC_N_GAP_specs_1;
asn_struct_free_f N_GAP_free;
asn_struct_print_f N_GAP_print;
asn_constr_check_f N_GAP_constraint;
ber_type_decoder_f N_GAP_decode_ber;
der_type_encoder_f N_GAP_encode_der;
xer_type_decoder_f N_GAP_decode_xer;
xer_type_encoder_f N_GAP_encode_xer;
oer_type_decoder_f N_GAP_decode_oer;
oer_type_encoder_f N_GAP_encode_oer;
per_type_decoder_f N_GAP_decode_uper;
per_type_encoder_f N_GAP_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _N_GAP_H_ */
#include <asn_internal.h>
