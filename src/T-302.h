/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_T_302_H_
#define	_T_302_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum T_302 {
	T_302_ms100	= 0,
	T_302_ms200	= 1,
	T_302_ms400	= 2,
	T_302_ms600	= 3,
	T_302_ms800	= 4,
	T_302_ms1000	= 5,
	T_302_ms1200	= 6,
	T_302_ms1400	= 7,
	T_302_ms1600	= 8,
	T_302_ms1800	= 9,
	T_302_ms2000	= 10,
	T_302_ms3000	= 11,
	T_302_ms4000	= 12,
	T_302_ms6000	= 13,
	T_302_ms8000	= 14,
	T_302_spare	= 15
} e_T_302;

/* T-302 */
typedef long	 T_302_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_T_302_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_T_302;
extern const asn_INTEGER_specifics_t asn_SPC_T_302_specs_1;
asn_struct_free_f T_302_free;
asn_struct_print_f T_302_print;
asn_constr_check_f T_302_constraint;
ber_type_decoder_f T_302_decode_ber;
der_type_encoder_f T_302_encode_der;
xer_type_decoder_f T_302_decode_xer;
xer_type_encoder_f T_302_encode_xer;
oer_type_decoder_f T_302_decode_oer;
oer_type_encoder_f T_302_encode_oer;
per_type_decoder_f T_302_decode_uper;
per_type_encoder_f T_302_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _T_302_H_ */
#include <asn_internal.h>