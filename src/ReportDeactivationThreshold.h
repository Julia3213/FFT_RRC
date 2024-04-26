/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_ReportDeactivationThreshold_H_
#define	_ReportDeactivationThreshold_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ReportDeactivationThreshold {
	ReportDeactivationThreshold_notApplicable	= 0,
	ReportDeactivationThreshold_t1	= 1,
	ReportDeactivationThreshold_t2	= 2,
	ReportDeactivationThreshold_t3	= 3,
	ReportDeactivationThreshold_t4	= 4,
	ReportDeactivationThreshold_t5	= 5,
	ReportDeactivationThreshold_t6	= 6,
	ReportDeactivationThreshold_t7	= 7
} e_ReportDeactivationThreshold;

/* ReportDeactivationThreshold */
typedef long	 ReportDeactivationThreshold_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ReportDeactivationThreshold_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ReportDeactivationThreshold;
extern const asn_INTEGER_specifics_t asn_SPC_ReportDeactivationThreshold_specs_1;
asn_struct_free_f ReportDeactivationThreshold_free;
asn_struct_print_f ReportDeactivationThreshold_print;
asn_constr_check_f ReportDeactivationThreshold_constraint;
ber_type_decoder_f ReportDeactivationThreshold_decode_ber;
der_type_encoder_f ReportDeactivationThreshold_encode_der;
xer_type_decoder_f ReportDeactivationThreshold_decode_xer;
xer_type_encoder_f ReportDeactivationThreshold_encode_xer;
oer_type_decoder_f ReportDeactivationThreshold_decode_oer;
oer_type_encoder_f ReportDeactivationThreshold_encode_oer;
per_type_decoder_f ReportDeactivationThreshold_decode_uper;
per_type_encoder_f ReportDeactivationThreshold_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ReportDeactivationThreshold_H_ */
#include <asn_internal.h>
