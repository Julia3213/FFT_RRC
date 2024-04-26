/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RadioFrequencyBandGSM_H_
#define	_RadioFrequencyBandGSM_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RadioFrequencyBandGSM {
	RadioFrequencyBandGSM_gsm450	= 0,
	RadioFrequencyBandGSM_gsm480	= 1,
	RadioFrequencyBandGSM_gsm850	= 2,
	RadioFrequencyBandGSM_gsm900P	= 3,
	RadioFrequencyBandGSM_gsm900E	= 4,
	RadioFrequencyBandGSM_gsm1800	= 5,
	RadioFrequencyBandGSM_gsm1900	= 6,
	RadioFrequencyBandGSM_spare9	= 7,
	RadioFrequencyBandGSM_spare8	= 8,
	RadioFrequencyBandGSM_spare7	= 9,
	RadioFrequencyBandGSM_spare6	= 10,
	RadioFrequencyBandGSM_spare5	= 11,
	RadioFrequencyBandGSM_spare4	= 12,
	RadioFrequencyBandGSM_spare3	= 13,
	RadioFrequencyBandGSM_spare2	= 14,
	RadioFrequencyBandGSM_spare1	= 15
} e_RadioFrequencyBandGSM;

/* RadioFrequencyBandGSM */
typedef long	 RadioFrequencyBandGSM_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RadioFrequencyBandGSM_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RadioFrequencyBandGSM;
extern const asn_INTEGER_specifics_t asn_SPC_RadioFrequencyBandGSM_specs_1;
asn_struct_free_f RadioFrequencyBandGSM_free;
asn_struct_print_f RadioFrequencyBandGSM_print;
asn_constr_check_f RadioFrequencyBandGSM_constraint;
ber_type_decoder_f RadioFrequencyBandGSM_decode_ber;
der_type_encoder_f RadioFrequencyBandGSM_encode_der;
xer_type_decoder_f RadioFrequencyBandGSM_decode_xer;
xer_type_encoder_f RadioFrequencyBandGSM_encode_xer;
oer_type_decoder_f RadioFrequencyBandGSM_decode_oer;
oer_type_encoder_f RadioFrequencyBandGSM_encode_oer;
per_type_decoder_f RadioFrequencyBandGSM_decode_uper;
per_type_encoder_f RadioFrequencyBandGSM_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _RadioFrequencyBandGSM_H_ */
#include <asn_internal.h>
