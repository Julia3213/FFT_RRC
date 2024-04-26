/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_EstablishmentCause_H_
#define	_EstablishmentCause_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EstablishmentCause {
	EstablishmentCause_originatingConversationalCall	= 0,
	EstablishmentCause_originatingStreamingCall	= 1,
	EstablishmentCause_originatingInteractiveCall	= 2,
	EstablishmentCause_originatingBackgroundCall	= 3,
	EstablishmentCause_originatingSubscribedTrafficCall	= 4,
	EstablishmentCause_terminatingConversationalCall	= 5,
	EstablishmentCause_terminatingStreamingCall	= 6,
	EstablishmentCause_terminatingInteractiveCall	= 7,
	EstablishmentCause_terminatingBackgroundCall	= 8,
	EstablishmentCause_emergencyCall	= 9,
	EstablishmentCause_interRAT_CellReselection	= 10,
	EstablishmentCause_interRAT_CellChangeOrder	= 11,
	EstablishmentCause_registration	= 12,
	EstablishmentCause_detach	= 13,
	EstablishmentCause_originatingHighPrioritySignalling	= 14,
	EstablishmentCause_originatingLowPrioritySignalling	= 15,
	EstablishmentCause_callRe_establishment	= 16,
	EstablishmentCause_terminatingHighPrioritySignalling	= 17,
	EstablishmentCause_terminatingLowPrioritySignalling	= 18,
	EstablishmentCause_terminatingCauseUnknown	= 19,
	EstablishmentCause_mbms_Reception	= 20,
	EstablishmentCause_mbms_PTP_RB_Request	= 21,
	EstablishmentCause_spare10	= 22,
	EstablishmentCause_spare9	= 23,
	EstablishmentCause_spare8	= 24,
	EstablishmentCause_spare7	= 25,
	EstablishmentCause_spare6	= 26,
	EstablishmentCause_spare5	= 27,
	EstablishmentCause_spare4	= 28,
	EstablishmentCause_spare3	= 29,
	EstablishmentCause_spare2	= 30,
	EstablishmentCause_spare1	= 31
} e_EstablishmentCause;

/* EstablishmentCause */
typedef long	 EstablishmentCause_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_EstablishmentCause_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_EstablishmentCause;
extern const asn_INTEGER_specifics_t asn_SPC_EstablishmentCause_specs_1;
asn_struct_free_f EstablishmentCause_free;
asn_struct_print_f EstablishmentCause_print;
asn_constr_check_f EstablishmentCause_constraint;
ber_type_decoder_f EstablishmentCause_decode_ber;
der_type_encoder_f EstablishmentCause_encode_der;
xer_type_decoder_f EstablishmentCause_decode_xer;
xer_type_encoder_f EstablishmentCause_encode_xer;
oer_type_decoder_f EstablishmentCause_decode_oer;
oer_type_encoder_f EstablishmentCause_encode_oer;
per_type_decoder_f EstablishmentCause_decode_uper;
per_type_encoder_f EstablishmentCause_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _EstablishmentCause_H_ */
#include <asn_internal.h>
