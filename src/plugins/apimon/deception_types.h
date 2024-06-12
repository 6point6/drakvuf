
#ifndef DECEPTION_TYPES_H
#define DECEPTION_TYPES_H

#include <vector>
#include "apimon.h"

enum class enum_mask_value_file
{
    FILE_WRITE_ATTRIBUTES = 1 << 0, // 1
    FILE_READ_ATTRIBUTES = 1 << 1, // 2
    FILE_EXECUTE = 1 << 2, // 4
    FILE_WRITE_EA = 1 << 3, // 8
    FILE_READ_EA = 1 << 4, // 16
    FILE_APPEND_DATA = 1 << 5, // 32
    FILE_WRITE_DATA = 1 << 6, // 64
    FILE_READ_DATA = 1 << 7,  // 128
    UNUSED_8 = 1 << 8,
    UNUSED_9 = 1 << 9,
    UNUSED_10 = 1 << 10,
    UNUSED_11 = 1 << 11,
    UNUSED_12 = 1 << 12,
    UNUSED_13 = 1 << 13,
    UNUSED_14 = 1 << 14,
    UNUSED_15 = 1 << 15,
    DELETE = 1 << 16,
    READ_CONTROL = 1 << 17,
    WRITE_DAC = 1 << 18, 
    WRITE_OWNER = 1 << 19,
    SYNCHRONIZE = 1 << 20,
    UNUSED_21 = 1 << 21,
    UNUSED_22 = 1 << 22,
    UNUSED_23 = 1 << 23,
    ACCESS_SYSTEM_SECURITY = 1 << 24,
    MAXIMUM_ALLOWED = 1 << 25,
    UNUSED_26 = 1 << 26,
    UNUSED_27 = 1 << 27,
    GENERIC_ALL = 1 << 28,
    GENERIC_EXECUTE = 1 << 29,
    GENERIC_WRITE = 1 << 30,
    GENERIC_READ = 1 << 31
};

struct  deception_config {
        bool enabled;                                   // Is the function turned on?
        bool active;                                    // Has the function been called and has a leftover effect?
        uint64_t overwritten_instruction;               // Example parameter to persist data over callbacks 
        addr_t overwrite_address;                       // Overwrite location
        std::string target_string;                      // Replace this with a vector so we're not wasting memory?
        std::string replacement_string;                 // As above?
        std::string target_string2;                      
        std::string replacement_string2;
        std::string target_string3;                      
        std::string replacement_string3;
        std::string target_string4;                      
        std::string replacement_string4;
        vmi_pid_t target_pid;
        uint64_t target_handle;
    };

struct deception_plugin_config {
    std::time_t last_update;
    deception_config ntcreatefile;
    deception_config netusergetinfo;
    deception_config lookupaccountsid;
    deception_config icmpsendecho2ex;
    deception_config ssldecryptpacket;
    deception_config findfirstornextfile;
    deception_config bcryptdecrypt;
    deception_config createtoolhelp32snapshot;
    deception_config process32firstw;
    deception_config filterfind;
    deception_config readprocessmemory;
};

typedef struct deception_plugin_config* deception_plugin_config_t;

typedef struct process {
  std::string name;
  vmi_pid_t pid;
} process;

typedef struct LUID {
	uint32_t LowPart;
	long HighPart;
} LUID;

typedef struct LSA_UNICODE_STRING {
	uint16_t Length;
	uint16_t MaximumLength;
	addr_t Buffer;
} LSA_UNICODE_STRING;

typedef struct _KIWI_MSV1_0_LIST_63 {
	addr_t Flink;	//off_2C5718
	addr_t Blink; //off_277380
	addr_t unk0; // unk_2C0AC8
	uint64_t unk1; // 0FFFFFFFFh
	addr_t unk2; // 0
	uint32_t unk3; // 0
	uint32_t unk4; // 0
	uint64_t unk5; // 0A0007D0h
	addr_t hSemaphore6; // 0F9Ch
	addr_t unk7; // 0
	uint64_t hSemaphore8; // 0FB8h
	addr_t unk9; // 0
	addr_t unk10; // 0
	uint32_t unk11; // 0
	uint32_t unk12; // 0 
	addr_t unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	uint8_t waza[16]; // to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domain;
	addr_t unk14;
	addr_t unk15;
	LSA_UNICODE_STRING Type;
	addr_t  pSid;
	uint64_t LogonType;
	addr_t unk18;
	uint64_t Session;
	int64_t LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	addr_t Credentials;
	addr_t unk19;
	addr_t unk20;
	addr_t unk21;
	uint32_t unk22;
	uint32_t unk23;
	uint32_t unk24;
	uint32_t unk25;
	uint32_t unk26;
	addr_t unk27;
	addr_t unk28;
	addr_t unk29;
	addr_t CredentialManager;
} KIWI_MSV1_0_LIST_63, *PKIWI_MSV1_0_LIST_63;

typedef struct system_info {
    vmi_pid_t lsass_pid;
} system_info;

typedef struct simple_user {
	addr_t pstruct_addr;
	std::string user_name;
	uint16_t max_user_len;
	std::string domain;
	uint16_t max_domain_len;
	std::string logon_server;
	uint16_t max_logsvr_len;
	addr_t pcredential_blob;
	int64_t logon_time;
	uint64_t session;
	uint64_t logon_type;
	std::string type;
	bool changed = false;
} simple_user;

#endif

