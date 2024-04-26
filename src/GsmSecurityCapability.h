/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_GsmSecurityCapability_H_
#define	_GsmSecurityCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum GsmSecurityCapability {
	GsmSecurityCapability_a5_7	= 0,
	GsmSecurityCapability_a5_6	= 1,
	GsmSecurityCapability_a5_5	= 2,
	GsmSecurityCapability_a5_4	= 3,
	GsmSecurityCapability_a5_3	= 4,
	GsmSecurityCapability_a5_2	= 5,
	GsmSecurityCapability_a5_1	= 6
} e_GsmSecurityCapability;

/* GsmSecurityCapability */
typedef BIT_STRING_t	 GsmSecurityCapability_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_GsmSecurityCapability_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_GsmSecurityCapability;
asn_struct_free_f GsmSecurityCapability_free;
asn_struct_print_f GsmSecurityCapability_print;
asn_constr_check_f GsmSecurityCapability_constraint;
ber_type_decoder_f GsmSecurityCapability_decode_ber;
der_type_encoder_f GsmSecurityCapability_encode_der;
xer_type_decoder_f GsmSecurityCapability_decode_xer;
xer_type_encoder_f GsmSecurityCapability_encode_xer;
oer_type_decoder_f GsmSecurityCapability_decode_oer;
oer_type_encoder_f GsmSecurityCapability_encode_oer;
per_type_decoder_f GsmSecurityCapability_decode_uper;
per_type_encoder_f GsmSecurityCapability_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _GsmSecurityCapability_H_ */
#include <asn_internal.h>
