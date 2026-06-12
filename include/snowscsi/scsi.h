#ifndef SNOWSCSI_SCSI_H
#define SNOWSCSI_SCSI_H

#include <stdint.h>

/* ── SCSI Opcodes ──────────────────────────────────────────────── */

#define SNOWSCSI_OP_TEST_UNIT_READY 0x00
#define SNOWSCSI_OP_REQUEST_SENSE 0x03
#define SNOWSCSI_OP_INQUIRY 0x12
#define SNOWSCSI_OP_READ_CAPACITY_10 0x25
#define SNOWSCSI_OP_READ_10 0x28
#define SNOWSCSI_OP_WRITE_10 0x2A

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
uint32_t snowscsi_cdb_get_lba10(const uint8_t *cdb);
uint16_t snowscsi_cdb_get_transfer_len10(const uint8_t *cdb);

#endif
