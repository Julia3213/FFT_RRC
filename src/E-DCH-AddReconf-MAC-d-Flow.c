/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "E-DCH-AddReconf-MAC-d-Flow.h"

static int
memb_maxMAC_e_PDUContents_constraint_7(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 19982)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_ms2_NonSchedTransmGrantHARQAlloc_constraint_7(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 8)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_maxMAC_e_PDUContents_constr_8 CC_NOTUSED = {
	{ 2, 1 }	/* (1..19982) */,
	-1};
static asn_per_constraints_t asn_PER_memb_maxMAC_e_PDUContents_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 15,  15,  1,  19982 }	/* (1..19982) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_ms2_NonSchedTransmGrantHARQAlloc_constr_9 CC_NOTUSED = {
	{ 0, 0 },
	8	/* (SIZE(8..8)) */};
static asn_per_constraints_t asn_PER_memb_ms2_NonSchedTransmGrantHARQAlloc_constr_9 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  8,  8 }	/* (SIZE(8..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_transmissionGrantType_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_transmissionGrantType_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_non_ScheduledTransGrantInfo_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType__non_ScheduledTransGrantInfo, maxMAC_e_PDUContents),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_maxMAC_e_PDUContents_constr_8, &asn_PER_memb_maxMAC_e_PDUContents_constr_8,  memb_maxMAC_e_PDUContents_constraint_7 },
		0, 0, /* No default value */
		"maxMAC-e-PDUContents"
		},
	{ ATF_POINTER, 1, offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType__non_ScheduledTransGrantInfo, ms2_NonSchedTransmGrantHARQAlloc),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_ms2_NonSchedTransmGrantHARQAlloc_constr_9, &asn_PER_memb_ms2_NonSchedTransmGrantHARQAlloc_constr_9,  memb_ms2_NonSchedTransmGrantHARQAlloc_constraint_7 },
		0, 0, /* No default value */
		"ms2-NonSchedTransmGrantHARQAlloc"
		},
};
static const int asn_MAP_non_ScheduledTransGrantInfo_oms_7[] = { 1 };
static const ber_tlv_tag_t asn_DEF_non_ScheduledTransGrantInfo_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_non_ScheduledTransGrantInfo_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxMAC-e-PDUContents */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ms2-NonSchedTransmGrantHARQAlloc */
};
static asn_SEQUENCE_specifics_t asn_SPC_non_ScheduledTransGrantInfo_specs_7 = {
	sizeof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType__non_ScheduledTransGrantInfo),
	offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType__non_ScheduledTransGrantInfo, _asn_ctx),
	asn_MAP_non_ScheduledTransGrantInfo_tag2el_7,
	2,	/* Count of tags in the map */
	asn_MAP_non_ScheduledTransGrantInfo_oms_7,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_non_ScheduledTransGrantInfo_7 = {
	"non-ScheduledTransGrantInfo",
	"non-ScheduledTransGrantInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_non_ScheduledTransGrantInfo_tags_7,
	sizeof(asn_DEF_non_ScheduledTransGrantInfo_tags_7)
		/sizeof(asn_DEF_non_ScheduledTransGrantInfo_tags_7[0]) - 1, /* 1 */
	asn_DEF_non_ScheduledTransGrantInfo_tags_7,	/* Same as above */
	sizeof(asn_DEF_non_ScheduledTransGrantInfo_tags_7)
		/sizeof(asn_DEF_non_ScheduledTransGrantInfo_tags_7[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_non_ScheduledTransGrantInfo_7,
	2,	/* Elements count */
	&asn_SPC_non_ScheduledTransGrantInfo_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_transmissionGrantType_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType, choice.non_ScheduledTransGrantInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_non_ScheduledTransGrantInfo_7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"non-ScheduledTransGrantInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType, choice.scheduledTransmissionGrantInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scheduledTransmissionGrantInfo"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_transmissionGrantType_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* non-ScheduledTransGrantInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* scheduledTransmissionGrantInfo */
};
static asn_CHOICE_specifics_t asn_SPC_transmissionGrantType_specs_6 = {
	sizeof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType),
	offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType, _asn_ctx),
	offsetof(struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType, present),
	sizeof(((struct E_DCH_AddReconf_MAC_d_Flow__transmissionGrantType *)0)->present),
	asn_MAP_transmissionGrantType_tag2el_6,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_transmissionGrantType_6 = {
	"transmissionGrantType",
	"transmissionGrantType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_transmissionGrantType_constr_6, &asn_PER_type_transmissionGrantType_constr_6, CHOICE_constraint },
	asn_MBR_transmissionGrantType_6,
	2,	/* Elements count */
	&asn_SPC_transmissionGrantType_specs_6	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_E_DCH_AddReconf_MAC_d_Flow_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_AddReconf_MAC_d_Flow, mac_d_FlowIdentity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_MAC_d_FlowIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mac-d-FlowIdentity"
		},
	{ ATF_POINTER, 4, offsetof(struct E_DCH_AddReconf_MAC_d_Flow, mac_d_FlowPowerOffset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_MAC_d_FlowPowerOffset,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mac-d-FlowPowerOffset"
		},
	{ ATF_POINTER, 3, offsetof(struct E_DCH_AddReconf_MAC_d_Flow, mac_d_FlowMaxRetrans),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_MAC_d_FlowMaxRetrans,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mac-d-FlowMaxRetrans"
		},
	{ ATF_POINTER, 2, offsetof(struct E_DCH_AddReconf_MAC_d_Flow, mac_d_FlowMultiplexingList),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_MAC_d_FlowMultiplexingList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mac-d-FlowMultiplexingList"
		},
	{ ATF_POINTER, 1, offsetof(struct E_DCH_AddReconf_MAC_d_Flow, transmissionGrantType),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_transmissionGrantType_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transmissionGrantType"
		},
};
static const int asn_MAP_E_DCH_AddReconf_MAC_d_Flow_oms_1[] = { 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_E_DCH_AddReconf_MAC_d_Flow_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mac-d-FlowIdentity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mac-d-FlowPowerOffset */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* mac-d-FlowMaxRetrans */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* mac-d-FlowMultiplexingList */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* transmissionGrantType */
};
asn_SEQUENCE_specifics_t asn_SPC_E_DCH_AddReconf_MAC_d_Flow_specs_1 = {
	sizeof(struct E_DCH_AddReconf_MAC_d_Flow),
	offsetof(struct E_DCH_AddReconf_MAC_d_Flow, _asn_ctx),
	asn_MAP_E_DCH_AddReconf_MAC_d_Flow_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_E_DCH_AddReconf_MAC_d_Flow_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_E_DCH_AddReconf_MAC_d_Flow = {
	"E-DCH-AddReconf-MAC-d-Flow",
	"E-DCH-AddReconf-MAC-d-Flow",
	&asn_OP_SEQUENCE,
	asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1,
	sizeof(asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1)
		/sizeof(asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1[0]), /* 1 */
	asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1)
		/sizeof(asn_DEF_E_DCH_AddReconf_MAC_d_Flow_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_E_DCH_AddReconf_MAC_d_Flow_1,
	5,	/* Elements count */
	&asn_SPC_E_DCH_AddReconf_MAC_d_Flow_specs_1	/* Additional specs */
};

