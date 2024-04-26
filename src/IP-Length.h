/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IP_Length_H_
#define	_IP_Length_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IP_Length {
	IP_Length_ipl5	= 0,
	IP_Length_ipl10	= 1
} e_IP_Length;

/* IP-Length */
typedef long	 IP_Length_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_IP_Length_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_IP_Length;
extern const asn_INTEGER_specifics_t asn_SPC_IP_Length_specs_1;
asn_struct_free_f IP_Length_free;
asn_struct_print_f IP_Length_print;
asn_constr_check_f IP_Length_constraint;
ber_type_decoder_f IP_Length_decode_ber;
der_type_encoder_f IP_Length_encode_der;
xer_type_decoder_f IP_Length_decode_xer;
xer_type_encoder_f IP_Length_encode_xer;
oer_type_decoder_f IP_Length_decode_oer;
oer_type_encoder_f IP_Length_encode_oer;
per_type_decoder_f IP_Length_decode_uper;
per_type_encoder_f IP_Length_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _IP_Length_H_ */
#include <asn_internal.h>
