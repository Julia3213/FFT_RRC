/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_RX_TX_TimeDifferenceType2Info_H_
#define	_UE_RX_TX_TimeDifferenceType2Info_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-RX-TX-TimeDifferenceType2.h"
#include "NeighbourQuality.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-RX-TX-TimeDifferenceType2Info */
typedef struct UE_RX_TX_TimeDifferenceType2Info {
	UE_RX_TX_TimeDifferenceType2_t	 ue_RX_TX_TimeDifferenceType2;
	NeighbourQuality_t	 neighbourQuality;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_RX_TX_TimeDifferenceType2Info_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_RX_TX_TimeDifferenceType2Info;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_RX_TX_TimeDifferenceType2Info_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_RX_TX_TimeDifferenceType2Info_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_RX_TX_TimeDifferenceType2Info_H_ */
#include <asn_internal.h>
