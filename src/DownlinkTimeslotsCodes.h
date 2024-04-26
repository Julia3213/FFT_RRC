/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DownlinkTimeslotsCodes_H_
#define	_DownlinkTimeslotsCodes_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IndividualTimeslotInfo.h"
#include "DL-TS-ChannelisationCodesShort.h"
#include <NULL.h>
#include <NativeInteger.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DownlinkTimeslotsCodes__moreTimeslots_PR {
	DownlinkTimeslotsCodes__moreTimeslots_PR_NOTHING,	/* No components present */
	DownlinkTimeslotsCodes__moreTimeslots_PR_noMore,
	DownlinkTimeslotsCodes__moreTimeslots_PR_additionalTimeslots
} DownlinkTimeslotsCodes__moreTimeslots_PR;
typedef enum DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR {
	DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR_NOTHING,	/* No components present */
	DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR_consecutive,
	DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR_timeslotList
} DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR;

/* Forward declarations */
struct DownlinkAdditionalTimeslots;

/* DownlinkTimeslotsCodes */
typedef struct DownlinkTimeslotsCodes {
	IndividualTimeslotInfo_t	 firstIndividualTimeslotInfo;
	DL_TS_ChannelisationCodesShort_t	 dl_TS_ChannelisationCodesShort;
	struct DownlinkTimeslotsCodes__moreTimeslots {
		DownlinkTimeslotsCodes__moreTimeslots_PR present;
		union DownlinkTimeslotsCodes__moreTimeslots_u {
			NULL_t	 noMore;
			struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots {
				DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR present;
				union DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots_u {
					long	 consecutive;
					struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots__timeslotList {
						A_SEQUENCE_OF(struct DownlinkAdditionalTimeslots) list;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} timeslotList;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} additionalTimeslots;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} moreTimeslots;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DownlinkTimeslotsCodes_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DownlinkTimeslotsCodes;
extern asn_SEQUENCE_specifics_t asn_SPC_DownlinkTimeslotsCodes_specs_1;
extern asn_TYPE_member_t asn_MBR_DownlinkTimeslotsCodes_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _DownlinkTimeslotsCodes_H_ */
#include <asn_internal.h>