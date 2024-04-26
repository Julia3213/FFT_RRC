/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellUpdateCause_ext_H_
#define	_CellUpdateCause_ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellUpdateCause_ext {
	CellUpdateCause_ext_mbms_Reception	= 0,
	CellUpdateCause_ext_mbms_PTP_RB_Request	= 1,
	CellUpdateCause_ext_spare2	= 2,
	CellUpdateCause_ext_spare1	= 3
} e_CellUpdateCause_ext;

/* CellUpdateCause-ext */
typedef long	 CellUpdateCause_ext_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CellUpdateCause_ext_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CellUpdateCause_ext;
extern const asn_INTEGER_specifics_t asn_SPC_CellUpdateCause_ext_specs_1;
asn_struct_free_f CellUpdateCause_ext_free;
asn_struct_print_f CellUpdateCause_ext_print;
asn_constr_check_f CellUpdateCause_ext_constraint;
ber_type_decoder_f CellUpdateCause_ext_decode_ber;
der_type_encoder_f CellUpdateCause_ext_encode_der;
xer_type_decoder_f CellUpdateCause_ext_decode_xer;
xer_type_encoder_f CellUpdateCause_ext_encode_xer;
oer_type_decoder_f CellUpdateCause_ext_decode_oer;
oer_type_encoder_f CellUpdateCause_ext_encode_oer;
per_type_decoder_f CellUpdateCause_ext_decode_uper;
per_type_encoder_f CellUpdateCause_ext_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CellUpdateCause_ext_H_ */
#include <asn_internal.h>
