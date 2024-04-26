/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MaxNumberOfReportingCellsType1_H_
#define	_MaxNumberOfReportingCellsType1_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MaxNumberOfReportingCellsType1 {
	MaxNumberOfReportingCellsType1_e1	= 0,
	MaxNumberOfReportingCellsType1_e2	= 1,
	MaxNumberOfReportingCellsType1_e3	= 2,
	MaxNumberOfReportingCellsType1_e4	= 3,
	MaxNumberOfReportingCellsType1_e5	= 4,
	MaxNumberOfReportingCellsType1_e6	= 5
} e_MaxNumberOfReportingCellsType1;

/* MaxNumberOfReportingCellsType1 */
typedef long	 MaxNumberOfReportingCellsType1_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MaxNumberOfReportingCellsType1_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MaxNumberOfReportingCellsType1;
extern const asn_INTEGER_specifics_t asn_SPC_MaxNumberOfReportingCellsType1_specs_1;
asn_struct_free_f MaxNumberOfReportingCellsType1_free;
asn_struct_print_f MaxNumberOfReportingCellsType1_print;
asn_constr_check_f MaxNumberOfReportingCellsType1_constraint;
ber_type_decoder_f MaxNumberOfReportingCellsType1_decode_ber;
der_type_encoder_f MaxNumberOfReportingCellsType1_encode_der;
xer_type_decoder_f MaxNumberOfReportingCellsType1_decode_xer;
xer_type_encoder_f MaxNumberOfReportingCellsType1_encode_xer;
oer_type_decoder_f MaxNumberOfReportingCellsType1_decode_oer;
oer_type_encoder_f MaxNumberOfReportingCellsType1_encode_oer;
per_type_decoder_f MaxNumberOfReportingCellsType1_decode_uper;
per_type_encoder_f MaxNumberOfReportingCellsType1_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MaxNumberOfReportingCellsType1_H_ */
#include <asn_internal.h>
