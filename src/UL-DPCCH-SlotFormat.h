/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_DPCCH_SlotFormat_H_
#define	_UL_DPCCH_SlotFormat_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_DPCCH_SlotFormat {
	UL_DPCCH_SlotFormat_slf0	= 0,
	UL_DPCCH_SlotFormat_slf1	= 1,
	UL_DPCCH_SlotFormat_slf2	= 2
} e_UL_DPCCH_SlotFormat;

/* UL-DPCCH-SlotFormat */
typedef long	 UL_DPCCH_SlotFormat_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_UL_DPCCH_SlotFormat_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_UL_DPCCH_SlotFormat;
extern const asn_INTEGER_specifics_t asn_SPC_UL_DPCCH_SlotFormat_specs_1;
asn_struct_free_f UL_DPCCH_SlotFormat_free;
asn_struct_print_f UL_DPCCH_SlotFormat_print;
asn_constr_check_f UL_DPCCH_SlotFormat_constraint;
ber_type_decoder_f UL_DPCCH_SlotFormat_decode_ber;
der_type_encoder_f UL_DPCCH_SlotFormat_encode_der;
xer_type_decoder_f UL_DPCCH_SlotFormat_decode_xer;
xer_type_encoder_f UL_DPCCH_SlotFormat_encode_xer;
oer_type_decoder_f UL_DPCCH_SlotFormat_decode_oer;
oer_type_encoder_f UL_DPCCH_SlotFormat_encode_oer;
per_type_decoder_f UL_DPCCH_SlotFormat_decode_uper;
per_type_encoder_f UL_DPCCH_SlotFormat_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_DPCCH_SlotFormat_H_ */
#include <asn_internal.h>
