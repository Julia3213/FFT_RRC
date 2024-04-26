/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_TS_ChannelisationCodesShort_H_
#define	_DL_TS_ChannelisationCodesShort_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include "DL-TS-ChannelisationCode.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_TS_ChannelisationCodesShort__codesRepresentation_PR {
	DL_TS_ChannelisationCodesShort__codesRepresentation_PR_NOTHING,	/* No components present */
	DL_TS_ChannelisationCodesShort__codesRepresentation_PR_consecutive,
	DL_TS_ChannelisationCodesShort__codesRepresentation_PR_bitmap
} DL_TS_ChannelisationCodesShort__codesRepresentation_PR;
typedef enum DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap {
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode16_SF16	= 0,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode15_SF16	= 1,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode14_SF16	= 2,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode13_SF16	= 3,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode12_SF16	= 4,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode11_SF16	= 5,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode10_SF16	= 6,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode9_SF16	= 7,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode8_SF16	= 8,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode7_SF16	= 9,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode6_SF16	= 10,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode5_SF16	= 11,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode4_SF16	= 12,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode3_SF16	= 13,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode2_SF16	= 14,
	DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap_chCode1_SF16	= 15
} e_DL_TS_ChannelisationCodesShort__codesRepresentation__bitmap;

/* DL-TS-ChannelisationCodesShort */
typedef struct DL_TS_ChannelisationCodesShort {
	struct DL_TS_ChannelisationCodesShort__codesRepresentation {
		DL_TS_ChannelisationCodesShort__codesRepresentation_PR present;
		union DL_TS_ChannelisationCodesShort__codesRepresentation_u {
			struct DL_TS_ChannelisationCodesShort__codesRepresentation__consecutive {
				DL_TS_ChannelisationCode_t	 firstChannelisationCode;
				DL_TS_ChannelisationCode_t	 lastChannelisationCode;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} consecutive;
			BIT_STRING_t	 bitmap;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} codesRepresentation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_TS_ChannelisationCodesShort_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_TS_ChannelisationCodesShort;
extern asn_SEQUENCE_specifics_t asn_SPC_DL_TS_ChannelisationCodesShort_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_TS_ChannelisationCodesShort_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _DL_TS_ChannelisationCodesShort_H_ */
#include <asn_internal.h>
