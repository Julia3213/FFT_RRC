/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CID_InclusionInfo_r4_H_
#define	_CID_InclusionInfo_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CID_InclusionInfo_r4 {
	CID_InclusionInfo_r4_pdcp_Header	= 0,
	CID_InclusionInfo_r4_rfc3095_PacketFormat	= 1
} e_CID_InclusionInfo_r4;

/* CID-InclusionInfo-r4 */
typedef long	 CID_InclusionInfo_r4_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CID_InclusionInfo_r4_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CID_InclusionInfo_r4;
extern const asn_INTEGER_specifics_t asn_SPC_CID_InclusionInfo_r4_specs_1;
asn_struct_free_f CID_InclusionInfo_r4_free;
asn_struct_print_f CID_InclusionInfo_r4_print;
asn_constr_check_f CID_InclusionInfo_r4_constraint;
ber_type_decoder_f CID_InclusionInfo_r4_decode_ber;
der_type_encoder_f CID_InclusionInfo_r4_encode_der;
xer_type_decoder_f CID_InclusionInfo_r4_decode_xer;
xer_type_encoder_f CID_InclusionInfo_r4_encode_xer;
oer_type_decoder_f CID_InclusionInfo_r4_decode_oer;
oer_type_encoder_f CID_InclusionInfo_r4_encode_oer;
per_type_decoder_f CID_InclusionInfo_r4_decode_uper;
per_type_encoder_f CID_InclusionInfo_r4_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CID_InclusionInfo_r4_H_ */
#include <asn_internal.h>
