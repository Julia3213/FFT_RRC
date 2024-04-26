/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_HorizontalWithVerticalVelocity_H_
#define	_HorizontalWithVerticalVelocity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HorizontalWithVerticalVelocity__verticalSpeedDirection {
	HorizontalWithVerticalVelocity__verticalSpeedDirection_upward	= 0,
	HorizontalWithVerticalVelocity__verticalSpeedDirection_downward	= 1
} e_HorizontalWithVerticalVelocity__verticalSpeedDirection;

/* HorizontalWithVerticalVelocity */
typedef struct HorizontalWithVerticalVelocity {
	long	 verticalSpeedDirection;
	long	 bearing;
	long	 horizontalSpeed;
	long	 verticalSpeed;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HorizontalWithVerticalVelocity_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_verticalSpeedDirection_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_HorizontalWithVerticalVelocity;
extern asn_SEQUENCE_specifics_t asn_SPC_HorizontalWithVerticalVelocity_specs_1;
extern asn_TYPE_member_t asn_MBR_HorizontalWithVerticalVelocity_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _HorizontalWithVerticalVelocity_H_ */
#include <asn_internal.h>
