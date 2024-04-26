/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMS-ServiceSchedulingInfo-r6.h"

#include "MBMS-ServiceTransmInfoList.h"
static int
memb_nextSchedulingperiod_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 31)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_nextSchedulingperiod_constr_4 CC_NOTUSED = {
	{ 1, 1 }	/* (0..31) */,
	-1};
static asn_per_constraints_t asn_PER_memb_nextSchedulingperiod_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 5,  5,  0,  31 }	/* (0..31) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_MBMS_ServiceSchedulingInfo_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_ServiceSchedulingInfo_r6, mbms_TransmissionIdentity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_TransmissionIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-TransmissionIdentity"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMS_ServiceSchedulingInfo_r6, mbms_ServiceTransmInfoList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_ServiceTransmInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-ServiceTransmInfoList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_ServiceSchedulingInfo_r6, nextSchedulingperiod),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_nextSchedulingperiod_constr_4, &asn_PER_memb_nextSchedulingperiod_constr_4,  memb_nextSchedulingperiod_constraint_1 },
		0, 0, /* No default value */
		"nextSchedulingperiod"
		},
};
static const int asn_MAP_MBMS_ServiceSchedulingInfo_r6_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMS_ServiceSchedulingInfo_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mbms-TransmissionIdentity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mbms-ServiceTransmInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* nextSchedulingperiod */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMS_ServiceSchedulingInfo_r6_specs_1 = {
	sizeof(struct MBMS_ServiceSchedulingInfo_r6),
	offsetof(struct MBMS_ServiceSchedulingInfo_r6, _asn_ctx),
	asn_MAP_MBMS_ServiceSchedulingInfo_r6_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_MBMS_ServiceSchedulingInfo_r6_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMS_ServiceSchedulingInfo_r6 = {
	"MBMS-ServiceSchedulingInfo-r6",
	"MBMS-ServiceSchedulingInfo-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1,
	sizeof(asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1)
		/sizeof(asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1[0]), /* 1 */
	asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1)
		/sizeof(asn_DEF_MBMS_ServiceSchedulingInfo_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMS_ServiceSchedulingInfo_r6_1,
	3,	/* Elements count */
	&asn_SPC_MBMS_ServiceSchedulingInfo_r6_specs_1	/* Additional specs */
};
