/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_NetworkAssistedGPS_Supported_H_
#define	_NetworkAssistedGPS_Supported_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NetworkAssistedGPS_Supported {
	NetworkAssistedGPS_Supported_networkBased	= 0,
	NetworkAssistedGPS_Supported_ue_Based	= 1,
	NetworkAssistedGPS_Supported_bothNetworkAndUE_Based	= 2,
	NetworkAssistedGPS_Supported_noNetworkAssistedGPS	= 3
} e_NetworkAssistedGPS_Supported;

/* NetworkAssistedGPS-Supported */
typedef long	 NetworkAssistedGPS_Supported_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NetworkAssistedGPS_Supported_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NetworkAssistedGPS_Supported;
extern const asn_INTEGER_specifics_t asn_SPC_NetworkAssistedGPS_Supported_specs_1;
asn_struct_free_f NetworkAssistedGPS_Supported_free;
asn_struct_print_f NetworkAssistedGPS_Supported_print;
asn_constr_check_f NetworkAssistedGPS_Supported_constraint;
ber_type_decoder_f NetworkAssistedGPS_Supported_decode_ber;
der_type_encoder_f NetworkAssistedGPS_Supported_encode_der;
xer_type_decoder_f NetworkAssistedGPS_Supported_decode_xer;
xer_type_encoder_f NetworkAssistedGPS_Supported_encode_xer;
oer_type_decoder_f NetworkAssistedGPS_Supported_decode_oer;
oer_type_encoder_f NetworkAssistedGPS_Supported_encode_oer;
per_type_decoder_f NetworkAssistedGPS_Supported_decode_uper;
per_type_encoder_f NetworkAssistedGPS_Supported_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _NetworkAssistedGPS_Supported_H_ */
#include <asn_internal.h>
