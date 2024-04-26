/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_DL_CCTrCh_H_
#define	_DL_CCTrCh_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TFCS-IdentityPlain.h"
#include "TimeInfo.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CommonTimeslotInfo;
struct DownlinkTimeslotsCodes;
struct UL_CCTrChTPCList;

/* DL-CCTrCh */
typedef struct DL_CCTrCh {
	TFCS_IdentityPlain_t	*tfcs_ID	/* DEFAULT 1 */;
	TimeInfo_t	 timeInfo;
	struct CommonTimeslotInfo	*commonTimeslotInfo	/* OPTIONAL */;
	struct DownlinkTimeslotsCodes	*dl_CCTrCH_TimeslotsCodes	/* OPTIONAL */;
	struct UL_CCTrChTPCList	*ul_CCTrChTPCList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_CCTrCh_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_CCTrCh;
extern asn_SEQUENCE_specifics_t asn_SPC_DL_CCTrCh_specs_1;
extern asn_TYPE_member_t asn_MBR_DL_CCTrCh_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _DL_CCTrCh_H_ */
#include <asn_internal.h>
