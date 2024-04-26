/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PDSCH_Identity_H_
#define	_PDSCH_Identity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PDSCH-Identity */
typedef long	 PDSCH_Identity_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PDSCH_Identity_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PDSCH_Identity;
asn_struct_free_f PDSCH_Identity_free;
asn_struct_print_f PDSCH_Identity_print;
asn_constr_check_f PDSCH_Identity_constraint;
ber_type_decoder_f PDSCH_Identity_decode_ber;
der_type_encoder_f PDSCH_Identity_encode_der;
xer_type_decoder_f PDSCH_Identity_decode_xer;
xer_type_encoder_f PDSCH_Identity_encode_xer;
oer_type_decoder_f PDSCH_Identity_decode_oer;
oer_type_encoder_f PDSCH_Identity_encode_oer;
per_type_decoder_f PDSCH_Identity_decode_uper;
per_type_encoder_f PDSCH_Identity_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PDSCH_Identity_H_ */
#include <asn_internal.h>
