/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TotalRLC_AM_BufferSize_r5_H_
#define	_TotalRLC_AM_BufferSize_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TotalRLC_AM_BufferSize_r5 {
	TotalRLC_AM_BufferSize_r5_kb10	= 0,
	TotalRLC_AM_BufferSize_r5_kb50	= 1,
	TotalRLC_AM_BufferSize_r5_kb100	= 2,
	TotalRLC_AM_BufferSize_r5_kb150	= 3,
	TotalRLC_AM_BufferSize_r5_kb200	= 4,
	TotalRLC_AM_BufferSize_r5_kb300	= 5,
	TotalRLC_AM_BufferSize_r5_kb400	= 6,
	TotalRLC_AM_BufferSize_r5_kb500	= 7,
	TotalRLC_AM_BufferSize_r5_kb750	= 8,
	TotalRLC_AM_BufferSize_r5_kb1000	= 9
} e_TotalRLC_AM_BufferSize_r5;

/* TotalRLC-AM-BufferSize-r5 */
typedef long	 TotalRLC_AM_BufferSize_r5_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TotalRLC_AM_BufferSize_r5_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TotalRLC_AM_BufferSize_r5;
extern const asn_INTEGER_specifics_t asn_SPC_TotalRLC_AM_BufferSize_r5_specs_1;
asn_struct_free_f TotalRLC_AM_BufferSize_r5_free;
asn_struct_print_f TotalRLC_AM_BufferSize_r5_print;
asn_constr_check_f TotalRLC_AM_BufferSize_r5_constraint;
ber_type_decoder_f TotalRLC_AM_BufferSize_r5_decode_ber;
der_type_encoder_f TotalRLC_AM_BufferSize_r5_encode_der;
xer_type_decoder_f TotalRLC_AM_BufferSize_r5_decode_xer;
xer_type_encoder_f TotalRLC_AM_BufferSize_r5_encode_xer;
oer_type_decoder_f TotalRLC_AM_BufferSize_r5_decode_oer;
oer_type_encoder_f TotalRLC_AM_BufferSize_r5_encode_oer;
per_type_decoder_f TotalRLC_AM_BufferSize_r5_decode_uper;
per_type_encoder_f TotalRLC_AM_BufferSize_r5_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TotalRLC_AM_BufferSize_r5_H_ */
#include <asn_internal.h>
