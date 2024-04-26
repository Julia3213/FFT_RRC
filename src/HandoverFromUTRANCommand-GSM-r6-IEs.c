/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "HandoverFromUTRANCommand-GSM-r6-IEs.h"

#include "RAB-InformationList-r6.h"
static asn_oer_constraints_t asn_OER_type_gsm_message_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_gsm_message_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_geran_SystemInfoType_constr_9 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_geran_SystemInfoType_constr_9 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const ber_tlv_tag_t asn_DEF_single_GSM_Message_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_single_GSM_Message_specs_6 = {
	sizeof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message__single_GSM_Message),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message__single_GSM_Message, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_single_GSM_Message_6 = {
	"single-GSM-Message",
	"single-GSM-Message",
	&asn_OP_SEQUENCE,
	asn_DEF_single_GSM_Message_tags_6,
	sizeof(asn_DEF_single_GSM_Message_tags_6)
		/sizeof(asn_DEF_single_GSM_Message_tags_6[0]) - 1, /* 1 */
	asn_DEF_single_GSM_Message_tags_6,	/* Same as above */
	sizeof(asn_DEF_single_GSM_Message_tags_6)
		/sizeof(asn_DEF_single_GSM_Message_tags_6[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_single_GSM_Message_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_gsm_MessageList_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message__gsm_MessageList, gsm_Messages),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GSM_MessageList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gsm-Messages"
		},
};
static const ber_tlv_tag_t asn_DEF_gsm_MessageList_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_gsm_MessageList_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* gsm-Messages */
};
static asn_SEQUENCE_specifics_t asn_SPC_gsm_MessageList_specs_7 = {
	sizeof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message__gsm_MessageList),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message__gsm_MessageList, _asn_ctx),
	asn_MAP_gsm_MessageList_tag2el_7,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_gsm_MessageList_7 = {
	"gsm-MessageList",
	"gsm-MessageList",
	&asn_OP_SEQUENCE,
	asn_DEF_gsm_MessageList_tags_7,
	sizeof(asn_DEF_gsm_MessageList_tags_7)
		/sizeof(asn_DEF_gsm_MessageList_tags_7[0]) - 1, /* 1 */
	asn_DEF_gsm_MessageList_tags_7,	/* Same as above */
	sizeof(asn_DEF_gsm_MessageList_tags_7)
		/sizeof(asn_DEF_gsm_MessageList_tags_7[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_gsm_MessageList_7,
	1,	/* Elements count */
	&asn_SPC_gsm_MessageList_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_gsm_message_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message, choice.single_GSM_Message),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_single_GSM_Message_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"single-GSM-Message"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message, choice.gsm_MessageList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_gsm_MessageList_7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gsm-MessageList"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_gsm_message_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* single-GSM-Message */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* gsm-MessageList */
};
static asn_CHOICE_specifics_t asn_SPC_gsm_message_specs_5 = {
	sizeof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message, _asn_ctx),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message, present),
	sizeof(((struct HandoverFromUTRANCommand_GSM_r6_IEs__gsm_message *)0)->present),
	asn_MAP_gsm_message_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_gsm_message_5 = {
	"gsm-message",
	"gsm-message",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_gsm_message_constr_5, &asn_PER_type_gsm_message_constr_5, CHOICE_constraint },
	asn_MBR_gsm_message_5,
	2,	/* Elements count */
	&asn_SPC_gsm_message_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_geran_SystemInfoType_9[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__geran_SystemInfoType, choice.sI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GERAN_SystemInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__geran_SystemInfoType, choice.pSI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GERAN_SystemInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pSI"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_geran_SystemInfoType_tag2el_9[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sI */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* pSI */
};
static asn_CHOICE_specifics_t asn_SPC_geran_SystemInfoType_specs_9 = {
	sizeof(struct HandoverFromUTRANCommand_GSM_r6_IEs__geran_SystemInfoType),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__geran_SystemInfoType, _asn_ctx),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs__geran_SystemInfoType, present),
	sizeof(((struct HandoverFromUTRANCommand_GSM_r6_IEs__geran_SystemInfoType *)0)->present),
	asn_MAP_geran_SystemInfoType_tag2el_9,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_geran_SystemInfoType_9 = {
	"geran-SystemInfoType",
	"geran-SystemInfoType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_geran_SystemInfoType_constr_9, &asn_PER_type_geran_SystemInfoType_constr_9, CHOICE_constraint },
	asn_MBR_geran_SystemInfoType_9,
	2,	/* Elements count */
	&asn_SPC_geran_SystemInfoType_specs_9	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_HandoverFromUTRANCommand_GSM_r6_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs, activationTime),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"activationTime"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs, toHandoverRAB_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAB_InformationList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"toHandoverRAB-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs, frequency_band),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Frequency_Band,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"frequency-band"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs, gsm_message),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_gsm_message_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gsm-message"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs, geran_SystemInfoType),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_geran_SystemInfoType_9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"geran-SystemInfoType"
		},
};
static const int asn_MAP_HandoverFromUTRANCommand_GSM_r6_IEs_oms_1[] = { 0, 1, 4 };
static const ber_tlv_tag_t asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_HandoverFromUTRANCommand_GSM_r6_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* activationTime */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* toHandoverRAB-Info */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* frequency-band */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* gsm-message */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* geran-SystemInfoType */
};
asn_SEQUENCE_specifics_t asn_SPC_HandoverFromUTRANCommand_GSM_r6_IEs_specs_1 = {
	sizeof(struct HandoverFromUTRANCommand_GSM_r6_IEs),
	offsetof(struct HandoverFromUTRANCommand_GSM_r6_IEs, _asn_ctx),
	asn_MAP_HandoverFromUTRANCommand_GSM_r6_IEs_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_HandoverFromUTRANCommand_GSM_r6_IEs_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs = {
	"HandoverFromUTRANCommand-GSM-r6-IEs",
	"HandoverFromUTRANCommand-GSM-r6-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1,
	sizeof(asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1[0]), /* 1 */
	asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANCommand_GSM_r6_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_HandoverFromUTRANCommand_GSM_r6_IEs_1,
	5,	/* Elements count */
	&asn_SPC_HandoverFromUTRANCommand_GSM_r6_IEs_specs_1	/* Additional specs */
};
