/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MaxRST_H_
#define	_MaxRST_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MaxRST {
	MaxRST_rst1	= 0,
	MaxRST_rst4	= 1,
	MaxRST_rst6	= 2,
	MaxRST_rst8	= 3,
	MaxRST_rst12	= 4,
	MaxRST_rst16	= 5,
	MaxRST_rst24	= 6,
	MaxRST_rst32	= 7
} e_MaxRST;

/* MaxRST */
typedef long	 MaxRST_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MaxRST_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MaxRST;
extern const asn_INTEGER_specifics_t asn_SPC_MaxRST_specs_1;
asn_struct_free_f MaxRST_free;
asn_struct_print_f MaxRST_print;
asn_constr_check_f MaxRST_constraint;
ber_type_decoder_f MaxRST_decode_ber;
der_type_encoder_f MaxRST_encode_der;
xer_type_decoder_f MaxRST_decode_xer;
xer_type_encoder_f MaxRST_encode_xer;
oer_type_decoder_f MaxRST_decode_oer;
oer_type_encoder_f MaxRST_encode_oer;
per_type_decoder_f MaxRST_decode_uper;
per_type_encoder_f MaxRST_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MaxRST_H_ */
#include <asn_internal.h>
