/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MonitoredCellRACH_List_H_
#define	_MonitoredCellRACH_List_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MonitoredCellRACH_Result;

/* MonitoredCellRACH-List */
typedef struct MonitoredCellRACH_List {
	A_SEQUENCE_OF(struct MonitoredCellRACH_Result) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MonitoredCellRACH_List_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MonitoredCellRACH_List;
extern asn_SET_OF_specifics_t asn_SPC_MonitoredCellRACH_List_specs_1;
extern asn_TYPE_member_t asn_MBR_MonitoredCellRACH_List_1[1];
extern asn_per_constraints_t asn_PER_type_MonitoredCellRACH_List_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _MonitoredCellRACH_List_H_ */
#include <asn_internal.h>