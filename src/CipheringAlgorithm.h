/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CipheringAlgorithm_H_
#define	_CipheringAlgorithm_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CipheringAlgorithm {
	CipheringAlgorithm_uea0	= 0,
	CipheringAlgorithm_uea1	= 1
} e_CipheringAlgorithm;

/* CipheringAlgorithm */
typedef long	 CipheringAlgorithm_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CipheringAlgorithm_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CipheringAlgorithm;
extern const asn_INTEGER_specifics_t asn_SPC_CipheringAlgorithm_specs_1;
asn_struct_free_f CipheringAlgorithm_free;
asn_struct_print_f CipheringAlgorithm_print;
asn_constr_check_f CipheringAlgorithm_constraint;
ber_type_decoder_f CipheringAlgorithm_decode_ber;
der_type_encoder_f CipheringAlgorithm_encode_der;
xer_type_decoder_f CipheringAlgorithm_decode_xer;
xer_type_encoder_f CipheringAlgorithm_encode_xer;
oer_type_decoder_f CipheringAlgorithm_decode_oer;
oer_type_encoder_f CipheringAlgorithm_encode_oer;
per_type_decoder_f CipheringAlgorithm_decode_uper;
per_type_encoder_f CipheringAlgorithm_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CipheringAlgorithm_H_ */
#include <asn_internal.h>
