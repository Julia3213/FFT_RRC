/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MinimumSpreadingFactor_H_
#define	_MinimumSpreadingFactor_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MinimumSpreadingFactor {
	MinimumSpreadingFactor_sf4	= 0,
	MinimumSpreadingFactor_sf8	= 1,
	MinimumSpreadingFactor_sf16	= 2,
	MinimumSpreadingFactor_sf32	= 3,
	MinimumSpreadingFactor_sf64	= 4,
	MinimumSpreadingFactor_sf128	= 5,
	MinimumSpreadingFactor_sf256	= 6
} e_MinimumSpreadingFactor;

/* MinimumSpreadingFactor */
typedef long	 MinimumSpreadingFactor_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MinimumSpreadingFactor_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MinimumSpreadingFactor;
extern const asn_INTEGER_specifics_t asn_SPC_MinimumSpreadingFactor_specs_1;
asn_struct_free_f MinimumSpreadingFactor_free;
asn_struct_print_f MinimumSpreadingFactor_print;
asn_constr_check_f MinimumSpreadingFactor_constraint;
ber_type_decoder_f MinimumSpreadingFactor_decode_ber;
der_type_encoder_f MinimumSpreadingFactor_encode_der;
xer_type_decoder_f MinimumSpreadingFactor_decode_xer;
xer_type_encoder_f MinimumSpreadingFactor_encode_xer;
oer_type_decoder_f MinimumSpreadingFactor_decode_oer;
oer_type_encoder_f MinimumSpreadingFactor_encode_oer;
per_type_decoder_f MinimumSpreadingFactor_decode_uper;
per_type_encoder_f MinimumSpreadingFactor_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MinimumSpreadingFactor_H_ */
#include <asn_internal.h>
