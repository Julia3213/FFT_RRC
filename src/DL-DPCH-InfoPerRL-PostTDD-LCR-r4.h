/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_DPCH_InfoPerRL_PostTDD_LCR_r4_H_
#define	_DL_DPCH_InfoPerRL_PostTDD_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DownlinkTimeslotsCodes-LCR-r4.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DL-DPCH-InfoPerRL-PostTDD-LCR-r4 */
typedef struct DL_DPCH_InfoPerRL_PostTDD_LCR_r4 {
	DownlinkTimeslotsCodes_LCR_r4_t	 dl_CCTrCH_TimeslotsCodes;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_DPCH_InfoPerRL_PostTDD_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_DPCH_InfoPerRL_PostTDD_LCR_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_DL_DPCH_InfoPerRL_PostTDD_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_DPCH_InfoPerRL_PostTDD_LCR_r4_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _DL_DPCH_InfoPerRL_PostTDD_LCR_r4_H_ */
#include <asn_internal.h>
