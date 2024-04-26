/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_TransChCapability_H_
#define	_DL_TransChCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MaxNoBits.h"
#include "TurboSupport.h"
#include "MaxSimultaneousTransChsDL.h"
#include "MaxSimultaneousCCTrCH-Count.h"
#include "MaxTransportBlocksDL.h"
#include "MaxNumberOfTFC-DL.h"
#include "MaxNumberOfTF.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DL-TransChCapability */
typedef struct DL_TransChCapability {
	MaxNoBits_t	 maxNoBitsReceived;
	MaxNoBits_t	 maxConvCodeBitsReceived;
	TurboSupport_t	 turboDecodingSupport;
	MaxSimultaneousTransChsDL_t	 maxSimultaneousTransChs;
	MaxSimultaneousCCTrCH_Count_t	 maxSimultaneousCCTrCH_Count;
	MaxTransportBlocksDL_t	 maxReceivedTransportBlocks;
	MaxNumberOfTFC_DL_t	 maxNumberOfTFC;
	MaxNumberOfTF_t	 maxNumberOfTF;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_TransChCapability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_TransChCapability;
extern asn_SEQUENCE_specifics_t asn_SPC_DL_TransChCapability_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_TransChCapability_1[8];

#ifdef __cplusplus
}
#endif

#endif	/* _DL_TransChCapability_H_ */
#include <asn_internal.h>
