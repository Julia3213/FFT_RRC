/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UplinkPhysicalChannelControl_r7_IEs_H_
#define	_UplinkPhysicalChannelControl_r7_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SpecialBurstScheduling.h"
#include "Alpha.h"
#include "ConstantValueTdd.h"
#include <constr_SEQUENCE.h>
#include <NativeInteger.h>
#include <NativeEnumerated.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UplinkPhysicalChannelControl_r7_IEs__tddOption_PR {
	UplinkPhysicalChannelControl_r7_IEs__tddOption_PR_NOTHING,	/* No components present */
	UplinkPhysicalChannelControl_r7_IEs__tddOption_PR_tdd384,
	UplinkPhysicalChannelControl_r7_IEs__tddOption_PR_tdd768,
	UplinkPhysicalChannelControl_r7_IEs__tddOption_PR_tdd128
} UplinkPhysicalChannelControl_r7_IEs__tddOption_PR;
typedef enum UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128__tpc_Step_Size {
	UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128__tpc_Step_Size_s1	= 0,
	UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128__tpc_Step_Size_s2	= 1,
	UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128__tpc_Step_Size_s3	= 2,
	UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128__tpc_Step_Size_spare1	= 3
} e_UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128__tpc_Step_Size;

/* Forward declarations */
struct CCTrCH_PowerControlInfo_r7;
struct UL_TimingAdvanceControl_r4;
struct OpenLoopPowerControl_IPDL_TDD_r4;
struct HS_SICH_Power_Control_Info_TDD384;
struct UL_TimingAdvanceControl_r7;
struct HS_SICH_Power_Control_Info_TDD768;
struct UL_SynchronisationParameters_r4;

/* UplinkPhysicalChannelControl-r7-IEs */
typedef struct UplinkPhysicalChannelControl_r7_IEs {
	struct CCTrCH_PowerControlInfo_r7	*ccTrCH_PowerControlInfo	/* OPTIONAL */;
	SpecialBurstScheduling_t	*specialBurstScheduling	/* OPTIONAL */;
	struct UplinkPhysicalChannelControl_r7_IEs__tddOption {
		UplinkPhysicalChannelControl_r7_IEs__tddOption_PR present;
		union UplinkPhysicalChannelControl_r7_IEs__tddOption_u {
			struct UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd384 {
				struct UL_TimingAdvanceControl_r4	*timingAdvance	/* OPTIONAL */;
				Alpha_t	*alpha	/* OPTIONAL */;
				ConstantValueTdd_t	*prach_ConstantValue	/* OPTIONAL */;
				ConstantValueTdd_t	*pusch_ConstantValue	/* OPTIONAL */;
				struct OpenLoopPowerControl_IPDL_TDD_r4	*openLoopPowerControl_IPDL_TDD	/* OPTIONAL */;
				struct HS_SICH_Power_Control_Info_TDD384	*hs_SICH_PowerControl	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd384;
			struct UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd768 {
				struct UL_TimingAdvanceControl_r7	*timingAdvance	/* OPTIONAL */;
				Alpha_t	*alpha	/* OPTIONAL */;
				ConstantValueTdd_t	*prach_ConstantValue	/* OPTIONAL */;
				ConstantValueTdd_t	*pusch_ConstantValue	/* OPTIONAL */;
				struct OpenLoopPowerControl_IPDL_TDD_r4	*openLoopPowerControl_IPDL_TDD	/* OPTIONAL */;
				struct HS_SICH_Power_Control_Info_TDD768	*hs_SICH_PowerControl	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd768;
			struct UplinkPhysicalChannelControl_r7_IEs__tddOption__tdd128 {
				struct UL_SynchronisationParameters_r4	*ul_SynchronisationParameters	/* OPTIONAL */;
				long	*desired_HS_SICH_PowerLevel	/* OPTIONAL */;
				long	*tpc_Step_Size	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd128;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tddOption;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UplinkPhysicalChannelControl_r7_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_tpc_Step_Size_22;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_UplinkPhysicalChannelControl_r7_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_UplinkPhysicalChannelControl_r7_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_UplinkPhysicalChannelControl_r7_IEs_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _UplinkPhysicalChannelControl_r7_IEs_H_ */
#include <asn_internal.h>