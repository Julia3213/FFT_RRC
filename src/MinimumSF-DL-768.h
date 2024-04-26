/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MinimumSF_DL_768_H_
#define	_MinimumSF_DL_768_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MinimumSF_DL_768 {
	MinimumSF_DL_768_sf1	= 0,
	MinimumSF_DL_768_sf32	= 1
} e_MinimumSF_DL_768;

/* MinimumSF-DL-768 */
typedef long	 MinimumSF_DL_768_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MinimumSF_DL_768_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MinimumSF_DL_768;
extern const asn_INTEGER_specifics_t asn_SPC_MinimumSF_DL_768_specs_1;
asn_struct_free_f MinimumSF_DL_768_free;
asn_struct_print_f MinimumSF_DL_768_print;
asn_constr_check_f MinimumSF_DL_768_constraint;
ber_type_decoder_f MinimumSF_DL_768_decode_ber;
der_type_encoder_f MinimumSF_DL_768_encode_der;
xer_type_decoder_f MinimumSF_DL_768_decode_xer;
xer_type_encoder_f MinimumSF_DL_768_encode_xer;
oer_type_decoder_f MinimumSF_DL_768_decode_oer;
oer_type_encoder_f MinimumSF_DL_768_encode_oer;
per_type_decoder_f MinimumSF_DL_768_decode_uper;
per_type_encoder_f MinimumSF_DL_768_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MinimumSF_DL_768_H_ */
#include <asn_internal.h>