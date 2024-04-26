/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_GERAN_SystemInfoBlock_H_
#define	_GERAN_SystemInfoBlock_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GERAN-SystemInfoBlock */
typedef OCTET_STRING_t	 GERAN_SystemInfoBlock_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_GERAN_SystemInfoBlock_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_GERAN_SystemInfoBlock;
asn_struct_free_f GERAN_SystemInfoBlock_free;
asn_struct_print_f GERAN_SystemInfoBlock_print;
asn_constr_check_f GERAN_SystemInfoBlock_constraint;
ber_type_decoder_f GERAN_SystemInfoBlock_decode_ber;
der_type_encoder_f GERAN_SystemInfoBlock_encode_der;
xer_type_decoder_f GERAN_SystemInfoBlock_decode_xer;
xer_type_encoder_f GERAN_SystemInfoBlock_encode_xer;
oer_type_decoder_f GERAN_SystemInfoBlock_decode_oer;
oer_type_encoder_f GERAN_SystemInfoBlock_encode_oer;
per_type_decoder_f GERAN_SystemInfoBlock_decode_uper;
per_type_encoder_f GERAN_SystemInfoBlock_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _GERAN_SystemInfoBlock_H_ */
#include <asn_internal.h>