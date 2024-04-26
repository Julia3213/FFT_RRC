/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_FreqQualityEstimateQuantity_TDD_H_
#define	_FreqQualityEstimateQuantity_TDD_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum FreqQualityEstimateQuantity_TDD {
	FreqQualityEstimateQuantity_TDD_primaryCCPCH_RSCP	= 0
} e_FreqQualityEstimateQuantity_TDD;

/* FreqQualityEstimateQuantity-TDD */
typedef long	 FreqQualityEstimateQuantity_TDD_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_FreqQualityEstimateQuantity_TDD_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_FreqQualityEstimateQuantity_TDD;
extern const asn_INTEGER_specifics_t asn_SPC_FreqQualityEstimateQuantity_TDD_specs_1;
asn_struct_free_f FreqQualityEstimateQuantity_TDD_free;
asn_struct_print_f FreqQualityEstimateQuantity_TDD_print;
asn_constr_check_f FreqQualityEstimateQuantity_TDD_constraint;
ber_type_decoder_f FreqQualityEstimateQuantity_TDD_decode_ber;
der_type_encoder_f FreqQualityEstimateQuantity_TDD_encode_der;
xer_type_decoder_f FreqQualityEstimateQuantity_TDD_decode_xer;
xer_type_encoder_f FreqQualityEstimateQuantity_TDD_encode_xer;
oer_type_decoder_f FreqQualityEstimateQuantity_TDD_decode_oer;
oer_type_encoder_f FreqQualityEstimateQuantity_TDD_encode_oer;
per_type_decoder_f FreqQualityEstimateQuantity_TDD_decode_uper;
per_type_encoder_f FreqQualityEstimateQuantity_TDD_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _FreqQualityEstimateQuantity_TDD_H_ */
#include <asn_internal.h>
