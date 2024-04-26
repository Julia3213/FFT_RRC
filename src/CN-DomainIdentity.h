/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CN_DomainIdentity_H_
#define	_CN_DomainIdentity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CN_DomainIdentity {
	CN_DomainIdentity_cs_domain	= 0,
	CN_DomainIdentity_ps_domain	= 1
} e_CN_DomainIdentity;

/* CN-DomainIdentity */
typedef long	 CN_DomainIdentity_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CN_DomainIdentity_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CN_DomainIdentity;
extern const asn_INTEGER_specifics_t asn_SPC_CN_DomainIdentity_specs_1;
asn_struct_free_f CN_DomainIdentity_free;
asn_struct_print_f CN_DomainIdentity_print;
asn_constr_check_f CN_DomainIdentity_constraint;
ber_type_decoder_f CN_DomainIdentity_decode_ber;
der_type_encoder_f CN_DomainIdentity_encode_der;
xer_type_decoder_f CN_DomainIdentity_decode_xer;
xer_type_encoder_f CN_DomainIdentity_encode_xer;
oer_type_decoder_f CN_DomainIdentity_decode_oer;
oer_type_encoder_f CN_DomainIdentity_encode_oer;
per_type_decoder_f CN_DomainIdentity_decode_uper;
per_type_encoder_f CN_DomainIdentity_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CN_DomainIdentity_H_ */
#include <asn_internal.h>
