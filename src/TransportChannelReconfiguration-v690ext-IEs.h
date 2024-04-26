/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TransportChannelReconfiguration_v690ext_IEs_H_
#define	_TransportChannelReconfiguration_v690ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DelayRestrictionFlag.h"
#include "HARQ-Preamble-Mode.h"
#include "BEACON-PL-Est.h"
#include <NativeEnumerated.h>
#include "DHS-Sync.h"
#include "TimingMaintainedSynchInd.h"
#include "MBMS-PL-ServiceRestrictInfo-r6.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TransportChannelReconfiguration_v690ext_IEs__postVerificationPeriod {
	TransportChannelReconfiguration_v690ext_IEs__postVerificationPeriod_true	= 0
} e_TransportChannelReconfiguration_v690ext_IEs__postVerificationPeriod;

/* Forward declarations */
struct PLMN_Identity;

/* TransportChannelReconfiguration-v690ext-IEs */
typedef struct TransportChannelReconfiguration_v690ext_IEs {
	DelayRestrictionFlag_t	*delayRestrictionFlag	/* OPTIONAL */;
	struct PLMN_Identity	*primary_plmn_Identity	/* OPTIONAL */;
	HARQ_Preamble_Mode_t	*harq_Preamble_Mode	/* OPTIONAL */;
	BEACON_PL_Est_t	*beaconPLEst	/* OPTIONAL */;
	long	*postVerificationPeriod	/* OPTIONAL */;
	DHS_Sync_t	*dhs_sync	/* OPTIONAL */;
	TimingMaintainedSynchInd_t	*timingMaintainedSynchInd	/* OPTIONAL */;
	MBMS_PL_ServiceRestrictInfo_r6_t	*mbms_PL_ServiceRestrictInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TransportChannelReconfiguration_v690ext_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_postVerificationPeriod_6;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_TransportChannelReconfiguration_v690ext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_TransportChannelReconfiguration_v690ext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_TransportChannelReconfiguration_v690ext_IEs_1[8];

#ifdef __cplusplus
}
#endif

#endif	/* _TransportChannelReconfiguration_v690ext_IEs_H_ */
#include <asn_internal.h>
