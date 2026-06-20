#ifndef SNOWSCSI_SCSI_H
#define SNOWSCSI_SCSI_H

#include <stdint.h>

/* ── SCSI Opcodes ──────────────────────────────────────────────── */

#define SNOWSCSI_OP_TEST_UNIT_READY 0x00
#define SNOWSCSI_OP_REQUEST_SENSE 0x03
#define SNOWSCSI_OP_READ_6 0x08
#define SNOWSCSI_OP_WRITE_6 0x0A
#define SNOWSCSI_OP_INQUIRY 0x12
#define SNOWSCSI_OP_READ_CAPACITY_10 0x25
#define SNOWSCSI_OP_READ_10 0x28
#define SNOWSCSI_OP_WRITE_10 0x2A
#define SNOWSCSI_OP_READ_16 0x88
#define SNOWSCSI_OP_WRITE_16 0x8A
#define SNOWSCSI_OP_SERVICE_ACTION_IN 0x9E
#define SNOWSCSI_OP_READ_12 0xA8
#define SNOWSCSI_OP_WRITE_12 0xAA
#define SNOWSCSI_OP_MODE_SENSE_6 0x1A
#define SNOWSCSI_OP_MODE_SENSE_10 0x5A
#define SNOWSCSI_OP_MODE_SELECT_6 0x15
#define SNOWSCSI_OP_MODE_SELECT_10 0x55
#define SNOWSCSI_OP_SYNCHRONIZE_CACHE_10 0x35
#define SNOWSCSI_OP_SEND_DIAGNOSTIC 0x1D
#define SNOWSCSI_OP_RECEIVE_DIAGNOSTIC 0x1C
#define SNOWSCSI_OP_REPORT_LUNS 0xA0
#define SNOWSCSI_OP_PREVENT_ALLOW 0x1E
#define SNOWSCSI_OP_START_STOP_UNIT 0x1B

/* ── Sense Keys ────────────────────────────────────────────────── */

typedef enum {
  SNOWSCSI_SENSE_NONE = 0x00,
  SNOWSCSI_SENSE_NOT_READY = 0x02,
  SNOWSCSI_SENSE_MEDIUM_ERROR = 0x03,
  SNOWSCSI_SENSE_ILLEGAL_REQUEST = 0x05,
  SNOWSCSI_SENSE_DATA_PROTECT = 0x07,
} snowscsi_sense_key_t;

/* ── ASC / ASCQ Constants ──────────────────────────────────────── */

#define SNOWSCSI_ASC_INVALID_COMMAND 0x20
#define SNOWSCSI_ASC_INVALID_FIELD 0x24
#define SNOWSCSI_ASC_LBA_OUT_OF_RANGE 0x21
#define SNOWSCSI_ASC_NOT_READY 0x04
#define SNOWSCSI_ASC_MEDIUM_NOT_PRESENT 0x3A
#define SNOWSCSI_ASC_WRITE_FAULT 0x03
#define SNOWSCSI_ASC_MEDIUM_REMOVAL_PREVENTED 0x53

/* ── Sense Data ────────────────────────────────────────────────── */

typedef struct {
  snowscsi_sense_key_t key;
  uint8_t asc;
  uint8_t ascq;
} snowscsi_sense_t;

/* ── Sense Helpers ─────────────────────────────────────────────── */

void snowscsi_sense_set(snowscsi_sense_t *s, snowscsi_sense_key_t key,
                        uint8_t asc, uint8_t ascq);

void snowscsi_sense_clear(snowscsi_sense_t *s);

/* ── CDB Parsing Helpers ───────────────────────────────────────── */

uint8_t snowscsi_cdb_get_opcode(const uint8_t *cdb);
uint32_t snowscsi_cdb_get_lba6(const uint8_t *cdb);
uint8_t snowscsi_cdb_get_transfer_len6(const uint8_t *cdb);
uint32_t snowscsi_cdb_get_lba10(const uint8_t *cdb);
uint16_t snowscsi_cdb_get_transfer_len10(const uint8_t *cdb);
uint32_t snowscsi_cdb_get_lba12(const uint8_t *cdb);
uint32_t snowscsi_cdb_get_transfer_len12(const uint8_t *cdb);
uint64_t snowscsi_cdb_get_lba16(const uint8_t *cdb);
uint32_t snowscsi_cdb_get_transfer_len16(const uint8_t *cdb);

const char *snowscsi_cdb_opcode_name(uint8_t opcode);

#endif
