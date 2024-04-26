/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_EllipsoidPointAltitude_H_
#define	_EllipsoidPointAltitude_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EllipsoidPointAltitude__latitudeSign {
	EllipsoidPointAltitude__latitudeSign_north	= 0,
	EllipsoidPointAltitude__latitudeSign_south	= 1
} e_EllipsoidPointAltitude__latitudeSign;
typedef enum EllipsoidPointAltitude__altitudeDirection {
	EllipsoidPointAltitude__altitudeDirection_height	= 0,
	EllipsoidPointAltitude__altitudeDirection_depth	= 1
} e_EllipsoidPointAltitude__altitudeDirection;

/* EllipsoidPointAltitude */
typedef struct EllipsoidPointAltitude {
	long	 latitudeSign;
	long	 latitude;
	long	 longitude;
	long	 altitudeDirection;
	long	 altitude;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EllipsoidPointAltitude_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_latitudeSign_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_altitudeDirection_7;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_EllipsoidPointAltitude;
extern asn_SEQUENCE_specifics_t asn_SPC_EllipsoidPointAltitude_specs_1;
extern asn_TYPE_member_t asn_MBR_EllipsoidPointAltitude_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _EllipsoidPointAltitude_H_ */
#include <asn_internal.h>
