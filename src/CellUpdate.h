/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellUpdate_H_
#define	_CellUpdate_H_


#include <asn_application.h>

/* Including external dependencies */
#include "U-RNTI.h"
#include "STARTList.h"
#include <BOOLEAN.h>
#include "CellUpdateCause.h"
#include "Rb-timer-indicator.h"
#include <BIT_STRING.h>
#include "CellUpdate-v590ext.h"
#include "CellUpdate-v690ext-IEs.h"
#include "CellUpdate-v7xyext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct FailureCauseWithProtErrTrId;
struct MeasuredResultsOnRACH;

/* CellUpdate */
typedef struct CellUpdate {
	U_RNTI_t	 u_RNTI;
	STARTList_t	 startList;
	BOOLEAN_t	 am_RLC_ErrorIndicationRb2_3or4;
	BOOLEAN_t	 am_RLC_ErrorIndicationRb5orAbove;
	CellUpdateCause_t	 cellUpdateCause;
	struct FailureCauseWithProtErrTrId	*failureCause	/* OPTIONAL */;
	Rb_timer_indicator_t	 rb_timer_indicator;
	struct MeasuredResultsOnRACH	*measuredResultsOnRACH	/* OPTIONAL */;
	struct CellUpdate__laterNonCriticalExtensions {
		BIT_STRING_t	*cellUpdate_r3_add_ext	/* OPTIONAL */;
		struct CellUpdate__laterNonCriticalExtensions__v590NonCriticalExtensions {
			CellUpdate_v590ext_t	 cellUpdate_v590ext;
			struct CellUpdate__laterNonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions {
				CellUpdate_v690ext_IEs_t	 cellUpdate_v690ext;
				struct CellUpdate__laterNonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions__v7xyNonCriticalExtensions {
					CellUpdate_v7xyext_IEs_t	 cellUpdate_v7xyext;
					struct CellUpdate__laterNonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions__v7xyNonCriticalExtensions__nonCriticalExtensions {
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *nonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *v7xyNonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v690NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v590NonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellUpdate_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellUpdate;
extern asn_SEQUENCE_specifics_t asn_SPC_CellUpdate_specs_1;
extern asn_TYPE_member_t asn_MBR_CellUpdate_1[9];

#ifdef __cplusplus
}
#endif

#endif	/* _CellUpdate_H_ */
#include <asn_internal.h>
