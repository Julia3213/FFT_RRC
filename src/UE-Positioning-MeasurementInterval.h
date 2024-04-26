/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_MeasurementInterval_H_
#define	_UE_Positioning_MeasurementInterval_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_Positioning_MeasurementInterval {
	UE_Positioning_MeasurementInterval_e5	= 0,
	UE_Positioning_MeasurementInterval_e15	= 1,
	UE_Positioning_MeasurementInterval_e60	= 2,
	UE_Positioning_MeasurementInterval_e300	= 3,
	UE_Positioning_MeasurementInterval_e900	= 4,
	UE_Positioning_MeasurementInterval_e1800	= 5,
	UE_Positioning_MeasurementInterval_e3600	= 6,
	UE_Positioning_MeasurementInterval_e7200	= 7
} e_UE_Positioning_MeasurementInterval;

/* UE-Positioning-MeasurementInterval */
typedef long	 UE_Positioning_MeasurementInterval_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_UE_Positioning_MeasurementInterval_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_MeasurementInterval;
extern const asn_INTEGER_specifics_t asn_SPC_UE_Positioning_MeasurementInterval_specs_1;
asn_struct_free_f UE_Positioning_MeasurementInterval_free;
asn_struct_print_f UE_Positioning_MeasurementInterval_print;
asn_constr_check_f UE_Positioning_MeasurementInterval_constraint;
ber_type_decoder_f UE_Positioning_MeasurementInterval_decode_ber;
der_type_encoder_f UE_Positioning_MeasurementInterval_encode_der;
xer_type_decoder_f UE_Positioning_MeasurementInterval_decode_xer;
xer_type_encoder_f UE_Positioning_MeasurementInterval_encode_xer;
oer_type_decoder_f UE_Positioning_MeasurementInterval_decode_oer;
oer_type_encoder_f UE_Positioning_MeasurementInterval_encode_oer;
per_type_decoder_f UE_Positioning_MeasurementInterval_decode_uper;
per_type_encoder_f UE_Positioning_MeasurementInterval_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_MeasurementInterval_H_ */
#include <asn_internal.h>