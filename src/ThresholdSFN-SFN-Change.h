/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_ThresholdSFN_SFN_Change_H_
#define	_ThresholdSFN_SFN_Change_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ThresholdSFN_SFN_Change {
	ThresholdSFN_SFN_Change_c0_25	= 0,
	ThresholdSFN_SFN_Change_c0_5	= 1,
	ThresholdSFN_SFN_Change_c1	= 2,
	ThresholdSFN_SFN_Change_c2	= 3,
	ThresholdSFN_SFN_Change_c3	= 4,
	ThresholdSFN_SFN_Change_c4	= 5,
	ThresholdSFN_SFN_Change_c5	= 6,
	ThresholdSFN_SFN_Change_c10	= 7,
	ThresholdSFN_SFN_Change_c20	= 8,
	ThresholdSFN_SFN_Change_c50	= 9,
	ThresholdSFN_SFN_Change_c100	= 10,
	ThresholdSFN_SFN_Change_c200	= 11,
	ThresholdSFN_SFN_Change_c500	= 12,
	ThresholdSFN_SFN_Change_c1000	= 13,
	ThresholdSFN_SFN_Change_c2000	= 14,
	ThresholdSFN_SFN_Change_c5000	= 15
} e_ThresholdSFN_SFN_Change;

/* ThresholdSFN-SFN-Change */
typedef long	 ThresholdSFN_SFN_Change_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ThresholdSFN_SFN_Change_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ThresholdSFN_SFN_Change;
extern const asn_INTEGER_specifics_t asn_SPC_ThresholdSFN_SFN_Change_specs_1;
asn_struct_free_f ThresholdSFN_SFN_Change_free;
asn_struct_print_f ThresholdSFN_SFN_Change_print;
asn_constr_check_f ThresholdSFN_SFN_Change_constraint;
ber_type_decoder_f ThresholdSFN_SFN_Change_decode_ber;
der_type_encoder_f ThresholdSFN_SFN_Change_encode_der;
xer_type_decoder_f ThresholdSFN_SFN_Change_decode_xer;
xer_type_encoder_f ThresholdSFN_SFN_Change_encode_xer;
oer_type_decoder_f ThresholdSFN_SFN_Change_decode_oer;
oer_type_encoder_f ThresholdSFN_SFN_Change_encode_oer;
per_type_decoder_f ThresholdSFN_SFN_Change_decode_uper;
per_type_encoder_f ThresholdSFN_SFN_Change_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ThresholdSFN_SFN_Change_H_ */
#include <asn_internal.h>
