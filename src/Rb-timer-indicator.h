/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_Rb_timer_indicator_H_
#define	_Rb_timer_indicator_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rb-timer-indicator */
typedef struct Rb_timer_indicator {
	BOOLEAN_t	 t314_expired;
	BOOLEAN_t	 t315_expired;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Rb_timer_indicator_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Rb_timer_indicator;
extern asn_SEQUENCE_specifics_t asn_SPC_Rb_timer_indicator_specs_1;
extern asn_TYPE_member_t asn_MBR_Rb_timer_indicator_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _Rb_timer_indicator_H_ */
#include <asn_internal.h>
