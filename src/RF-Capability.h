/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RF_Capability_H_
#define	_RF_Capability_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UE-PowerClass.h"
#include "TxRxFrequencySeparation.h"
#include <constr_SEQUENCE.h>
#include "RadioFrequencyBandTDDList.h"
#include "ChipRateCapability.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RF-Capability */
typedef struct RF_Capability {
	struct RF_Capability__fddRF_Capability {
		UE_PowerClass_t	 ue_PowerClass;
		TxRxFrequencySeparation_t	 txRxFrequencySeparation;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *fddRF_Capability;
	struct RF_Capability__tddRF_Capability {
		UE_PowerClass_t	 ue_PowerClass;
		RadioFrequencyBandTDDList_t	 radioFrequencyTDDBandList;
		ChipRateCapability_t	 chipRateCapability;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *tddRF_Capability;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RF_Capability_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RF_Capability;
extern asn_SEQUENCE_specifics_t asn_SPC_RF_Capability_specs_1;
extern asn_TYPE_member_t asn_MBR_RF_Capability_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RF_Capability_H_ */
#include <asn_internal.h>
