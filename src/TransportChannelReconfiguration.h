/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TransportChannelReconfiguration_H_
#define	_TransportChannelReconfiguration_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TransportChannelReconfiguration-r3-IEs.h"
#include "TransportChannelReconfiguration-v3a0ext.h"
#include <BIT_STRING.h>
#include "TransportChannelReconfiguration-v4b0ext-IEs.h"
#include "TransportChannelReconfiguration-v590ext-IEs.h"
#include "TransportChannelReconfiguration-v690ext-IEs.h"
#include <constr_SEQUENCE.h>
#include "RRC-TransactionIdentifier.h"
#include "TransportChannelReconfiguration-r4-IEs.h"
#include "TransportChannelReconfiguration-r5-IEs.h"
#include "TransportChannelReconfiguration-r6-IEs.h"
#include "TransportChannelReconfiguration-r7-IEs.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TransportChannelReconfiguration_PR {
	TransportChannelReconfiguration_PR_NOTHING,	/* No components present */
	TransportChannelReconfiguration_PR_r3,
	TransportChannelReconfiguration_PR_later_than_r3
} TransportChannelReconfiguration_PR;
typedef enum TransportChannelReconfiguration__later_than_r3__criticalExtensions_PR {
	TransportChannelReconfiguration__later_than_r3__criticalExtensions_PR_NOTHING,	/* No components present */
	TransportChannelReconfiguration__later_than_r3__criticalExtensions_PR_r4,
	TransportChannelReconfiguration__later_than_r3__criticalExtensions_PR_criticalExtensions
} TransportChannelReconfiguration__later_than_r3__criticalExtensions_PR;
typedef enum TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR {
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR_r5,
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR_criticalExtensions
} TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR;
typedef enum TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_r6,
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR;
typedef enum TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_r7,
	TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR;

/* TransportChannelReconfiguration */
typedef struct TransportChannelReconfiguration {
	TransportChannelReconfiguration_PR present;
	union TransportChannelReconfiguration_u {
		struct TransportChannelReconfiguration__r3 {
			TransportChannelReconfiguration_r3_IEs_t	 transportChannelReconfiguration_r3;
			struct TransportChannelReconfiguration__r3__v3a0NonCriticalExtensions {
				TransportChannelReconfiguration_v3a0ext_t	 transportChannelReconfiguration_v3a0ext;
				struct TransportChannelReconfiguration__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions {
					BIT_STRING_t	*transportChannelReconfiguration_r3_add_ext	/* OPTIONAL */;
					struct TransportChannelReconfiguration__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions {
						TransportChannelReconfiguration_v4b0ext_IEs_t	 transportChannelReconfiguration_v4b0ext;
						struct TransportChannelReconfiguration__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions {
							TransportChannelReconfiguration_v590ext_IEs_t	 transportChannelReconfiguration_v590ext;
							struct TransportChannelReconfiguration__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions {
								TransportChannelReconfiguration_v690ext_IEs_t	 transportChannelReconfiguration_v690ext;
								struct TransportChannelReconfiguration__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions__nonCriticalExtensions {
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *nonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v690NonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v590NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v4b0NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *laterNonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v3a0NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct TransportChannelReconfiguration__later_than_r3 {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct TransportChannelReconfiguration__later_than_r3__criticalExtensions {
				TransportChannelReconfiguration__later_than_r3__criticalExtensions_PR present;
				union TransportChannelReconfiguration__later_than_r3__criticalExtensions_u {
					struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__r4 {
						TransportChannelReconfiguration_r4_IEs_t	 transportChannelReconfiguration_r4;
						struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions {
							BIT_STRING_t	*transportChannelReconfiguration_r4_add_ext	/* OPTIONAL */;
							struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions {
								TransportChannelReconfiguration_v590ext_IEs_t	 transportChannelReconfiguration_v590ext;
								struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions {
									TransportChannelReconfiguration_v690ext_IEs_t	 transportChannelReconfiguration_v690ext;
									struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions__v690NonCriticalExtensions__nonCriticalExtensions {
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *nonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v690NonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v590NonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v4d0NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} r4;
					struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions {
						TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR present;
						union TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_u {
							struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5 {
								TransportChannelReconfiguration_r5_IEs_t	 transportChannelReconfiguration_r5;
								BIT_STRING_t	*transportChannelReconfiguration_r5_add_ext	/* OPTIONAL */;
								struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5__v690NonCriticalExtensions {
									TransportChannelReconfiguration_v690ext_IEs_t	 transportChannelReconfiguration_v690ext;
									struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5__v690NonCriticalExtensions__nonCriticalExtensions {
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *nonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v690NonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} r5;
							struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions {
								TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
								union TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_u {
									struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r6 {
										TransportChannelReconfiguration_r6_IEs_t	 transportChannelReconfiguration_r6;
										BIT_STRING_t	*transportChannelReconfiguration_r6_add_ext	/* OPTIONAL */;
										struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r6__nonCriticalExtensions {
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *nonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} r6;
									struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
										TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
										union TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_u {
											struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__r7 {
												TransportChannelReconfiguration_r7_IEs_t	 transportChannelReconfiguration_r7;
												BIT_STRING_t	*transportChannelReconfiguration_r7_add_ext	/* OPTIONAL */;
												struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__r7__nonCriticalExtensions {
													
													/* Context for parsing across buffer boundaries */
													asn_struct_ctx_t _asn_ctx;
												} *nonCriticalExtensions;
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} r7;
											struct TransportChannelReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} criticalExtensions;
										} choice;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} criticalExtensions;
								} choice;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} criticalExtensions;
						} choice;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} criticalExtensions;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} later_than_r3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TransportChannelReconfiguration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TransportChannelReconfiguration;
extern asn_CHOICE_specifics_t asn_SPC_TransportChannelReconfiguration_specs_1;
extern asn_TYPE_member_t asn_MBR_TransportChannelReconfiguration_1[2];
extern asn_per_constraints_t asn_PER_type_TransportChannelReconfiguration_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _TransportChannelReconfiguration_H_ */
#include <asn_internal.h>
