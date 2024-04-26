/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PDCP_PDU_Header_H_
#define	_PDCP_PDU_Header_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PDCP_PDU_Header {
	PDCP_PDU_Header_present	= 0,
	PDCP_PDU_Header_absent	= 1
} e_PDCP_PDU_Header;

/* PDCP-PDU-Header */
typedef long	 PDCP_PDU_Header_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PDCP_PDU_Header_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PDCP_PDU_Header;
extern const asn_INTEGER_specifics_t asn_SPC_PDCP_PDU_Header_specs_1;
asn_struct_free_f PDCP_PDU_Header_free;
asn_struct_print_f PDCP_PDU_Header_print;
asn_constr_check_f PDCP_PDU_Header_constraint;
ber_type_decoder_f PDCP_PDU_Header_decode_ber;
der_type_encoder_f PDCP_PDU_Header_encode_der;
xer_type_decoder_f PDCP_PDU_Header_decode_xer;
xer_type_encoder_f PDCP_PDU_Header_encode_xer;
oer_type_decoder_f PDCP_PDU_Header_decode_oer;
oer_type_encoder_f PDCP_PDU_Header_encode_oer;
per_type_decoder_f PDCP_PDU_Header_decode_uper;
per_type_encoder_f PDCP_PDU_Header_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PDCP_PDU_Header_H_ */
#include <asn_internal.h>
