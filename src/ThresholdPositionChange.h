/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_ThresholdPositionChange_H_
#define	_ThresholdPositionChange_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ThresholdPositionChange {
	ThresholdPositionChange_pc10	= 0,
	ThresholdPositionChange_pc20	= 1,
	ThresholdPositionChange_pc30	= 2,
	ThresholdPositionChange_pc40	= 3,
	ThresholdPositionChange_pc50	= 4,
	ThresholdPositionChange_pc100	= 5,
	ThresholdPositionChange_pc200	= 6,
	ThresholdPositionChange_pc300	= 7,
	ThresholdPositionChange_pc500	= 8,
	ThresholdPositionChange_pc1000	= 9,
	ThresholdPositionChange_pc2000	= 10,
	ThresholdPositionChange_pc5000	= 11,
	ThresholdPositionChange_pc10000	= 12,
	ThresholdPositionChange_pc20000	= 13,
	ThresholdPositionChange_pc50000	= 14,
	ThresholdPositionChange_pc100000	= 15
} e_ThresholdPositionChange;

/* ThresholdPositionChange */
typedef long	 ThresholdPositionChange_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ThresholdPositionChange_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ThresholdPositionChange;
extern const asn_INTEGER_specifics_t asn_SPC_ThresholdPositionChange_specs_1;
asn_struct_free_f ThresholdPositionChange_free;
asn_struct_print_f ThresholdPositionChange_print;
asn_constr_check_f ThresholdPositionChange_constraint;
ber_type_decoder_f ThresholdPositionChange_decode_ber;
der_type_encoder_f ThresholdPositionChange_encode_der;
xer_type_decoder_f ThresholdPositionChange_decode_xer;
xer_type_encoder_f ThresholdPositionChange_encode_xer;
oer_type_decoder_f ThresholdPositionChange_decode_oer;
oer_type_encoder_f ThresholdPositionChange_encode_oer;
per_type_decoder_f ThresholdPositionChange_decode_uper;
per_type_encoder_f ThresholdPositionChange_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ThresholdPositionChange_H_ */
#include <asn_internal.h>