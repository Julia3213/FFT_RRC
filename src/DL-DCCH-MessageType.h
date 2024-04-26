/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Class-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_DCCH_MessageType_H_
#define	_DL_DCCH_MessageType_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ActiveSetUpdate.h"
#include "AssistanceDataDelivery.h"
#include "CellChangeOrderFromUTRAN.h"
#include "CellUpdateConfirm.h"
#include "CounterCheck.h"
#include "DownlinkDirectTransfer.h"
#include "HandoverFromUTRANCommand-GSM.h"
#include "HandoverFromUTRANCommand-CDMA2000.h"
#include "MeasurementControl.h"
#include "PagingType2.h"
#include "PhysicalChannelReconfiguration.h"
#include "PhysicalSharedChannelAllocation.h"
#include "RadioBearerReconfiguration.h"
#include "RadioBearerRelease.h"
#include "RadioBearerSetup.h"
#include "RRCConnectionRelease.h"
#include "SecurityModeCommand.h"
#include "SignallingConnectionRelease.h"
#include "TransportChannelReconfiguration.h"
#include "TransportFormatCombinationControl.h"
#include "UECapabilityEnquiry.h"
#include "UECapabilityInformationConfirm.h"
#include "UplinkPhysicalChannelControl.h"
#include "URAUpdateConfirm.h"
#include "UTRANMobilityInformation.h"
#include "HandoverFromUTRANCommand-GERANIu.h"
#include "MBMSModifiedServicesInformation.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_DCCH_MessageType_PR {
	DL_DCCH_MessageType_PR_NOTHING,	/* No components present */
	DL_DCCH_MessageType_PR_activeSetUpdate,
	DL_DCCH_MessageType_PR_assistanceDataDelivery,
	DL_DCCH_MessageType_PR_cellChangeOrderFromUTRAN,
	DL_DCCH_MessageType_PR_cellUpdateConfirm,
	DL_DCCH_MessageType_PR_counterCheck,
	DL_DCCH_MessageType_PR_downlinkDirectTransfer,
	DL_DCCH_MessageType_PR_handoverFromUTRANCommand_GSM,
	DL_DCCH_MessageType_PR_handoverFromUTRANCommand_CDMA2000,
	DL_DCCH_MessageType_PR_measurementControl,
	DL_DCCH_MessageType_PR_pagingType2,
	DL_DCCH_MessageType_PR_physicalChannelReconfiguration,
	DL_DCCH_MessageType_PR_physicalSharedChannelAllocation,
	DL_DCCH_MessageType_PR_radioBearerReconfiguration,
	DL_DCCH_MessageType_PR_radioBearerRelease,
	DL_DCCH_MessageType_PR_radioBearerSetup,
	DL_DCCH_MessageType_PR_rrcConnectionRelease,
	DL_DCCH_MessageType_PR_securityModeCommand,
	DL_DCCH_MessageType_PR_signallingConnectionRelease,
	DL_DCCH_MessageType_PR_transportChannelReconfiguration,
	DL_DCCH_MessageType_PR_transportFormatCombinationControl,
	DL_DCCH_MessageType_PR_ueCapabilityEnquiry,
	DL_DCCH_MessageType_PR_ueCapabilityInformationConfirm,
	DL_DCCH_MessageType_PR_uplinkPhysicalChannelControl,
	DL_DCCH_MessageType_PR_uraUpdateConfirm,
	DL_DCCH_MessageType_PR_utranMobilityInformation,
	DL_DCCH_MessageType_PR_handoverFromUTRANCommand_GERANIu,
	DL_DCCH_MessageType_PR_mbmsModifiedServicesInformation,
	DL_DCCH_MessageType_PR_spare5,
	DL_DCCH_MessageType_PR_spare4,
	DL_DCCH_MessageType_PR_spare3,
	DL_DCCH_MessageType_PR_spare2,
	DL_DCCH_MessageType_PR_spare1
} DL_DCCH_MessageType_PR;

/* DL-DCCH-MessageType */
typedef struct DL_DCCH_MessageType {
	DL_DCCH_MessageType_PR present;
	union DL_DCCH_MessageType_u {
		ActiveSetUpdate_t	 activeSetUpdate;
		AssistanceDataDelivery_t	 assistanceDataDelivery;
		CellChangeOrderFromUTRAN_t	 cellChangeOrderFromUTRAN;
		CellUpdateConfirm_t	 cellUpdateConfirm;
		CounterCheck_t	 counterCheck;
		DownlinkDirectTransfer_t	 downlinkDirectTransfer;
		HandoverFromUTRANCommand_GSM_t	 handoverFromUTRANCommand_GSM;
		HandoverFromUTRANCommand_CDMA2000_t	 handoverFromUTRANCommand_CDMA2000;
		MeasurementControl_t	 measurementControl;
		PagingType2_t	 pagingType2;
		PhysicalChannelReconfiguration_t	 physicalChannelReconfiguration;
		PhysicalSharedChannelAllocation_t	 physicalSharedChannelAllocation;
		RadioBearerReconfiguration_t	 radioBearerReconfiguration;
		RadioBearerRelease_t	 radioBearerRelease;
		RadioBearerSetup_t	 radioBearerSetup;
		RRCConnectionRelease_t	 rrcConnectionRelease;
		SecurityModeCommand_t	 securityModeCommand;
		SignallingConnectionRelease_t	 signallingConnectionRelease;
		TransportChannelReconfiguration_t	 transportChannelReconfiguration;
		TransportFormatCombinationControl_t	 transportFormatCombinationControl;
		UECapabilityEnquiry_t	 ueCapabilityEnquiry;
		UECapabilityInformationConfirm_t	 ueCapabilityInformationConfirm;
		UplinkPhysicalChannelControl_t	 uplinkPhysicalChannelControl;
		URAUpdateConfirm_t	 uraUpdateConfirm;
		UTRANMobilityInformation_t	 utranMobilityInformation;
		HandoverFromUTRANCommand_GERANIu_t	 handoverFromUTRANCommand_GERANIu;
		MBMSModifiedServicesInformation_t	 mbmsModifiedServicesInformation;
		NULL_t	 spare5;
		NULL_t	 spare4;
		NULL_t	 spare3;
		NULL_t	 spare2;
		NULL_t	 spare1;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_DCCH_MessageType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_DCCH_MessageType;
extern asn_CHOICE_specifics_t asn_SPC_DL_DCCH_MessageType_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_DCCH_MessageType_1[32];
extern asn_per_constraints_t asn_PER_type_DL_DCCH_MessageType_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_DCCH_MessageType_H_ */
#include <asn_internal.h>
