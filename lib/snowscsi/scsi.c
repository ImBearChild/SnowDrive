#include <snowscsi/scsi.h>

void snowscsi_sense_set(snowscsi_sense_t *s, snowscsi_sense_key_t key,
                        uint8_t asc, uint8_t ascq) {
  s->key = key;
  s->asc = asc;
  s->ascq = ascq;
}

void snowscsi_sense_clear(snowscsi_sense_t *s) {
  s->key = SNOWSCSI_SENSE_NONE;
  s->asc = 0;
  s->ascq = 0;
}

uint8_t snowscsi_cdb_get_opcode(const uint8_t *cdb) { return cdb[0]; }

uint32_t snowscsi_cdb_get_lba6(const uint8_t *cdb) {
  return ((uint32_t)(cdb[1] & 0x1F) << 16) | ((uint32_t)cdb[2] << 8) |
         (uint32_t)cdb[3];
}

uint8_t snowscsi_cdb_get_transfer_len6(const uint8_t *cdb) {
  return cdb[4];
}

uint32_t snowscsi_cdb_get_lba10(const uint8_t *cdb) {
  return ((uint32_t)cdb[2] << 24) | ((uint32_t)cdb[3] << 16) |
         ((uint32_t)cdb[4] << 8) | ((uint32_t)cdb[5]);
}

uint16_t snowscsi_cdb_get_transfer_len10(const uint8_t *cdb) {
  return ((uint16_t)cdb[7] << 8) | ((uint16_t)cdb[8]);
}

uint32_t snowscsi_cdb_get_lba12(const uint8_t *cdb) {
  return ((uint32_t)cdb[2] << 24) | ((uint32_t)cdb[3] << 16) |
         ((uint32_t)cdb[4] << 8) | ((uint32_t)cdb[5]);
}

uint32_t snowscsi_cdb_get_transfer_len12(const uint8_t *cdb) {
  return ((uint32_t)cdb[6] << 24) | ((uint32_t)cdb[7] << 16) |
         ((uint32_t)cdb[8] << 8) | (uint32_t)cdb[9];
}

uint64_t snowscsi_cdb_get_lba16(const uint8_t *cdb) {
  return ((uint64_t)cdb[2] << 56) | ((uint64_t)cdb[3] << 48) |
         ((uint64_t)cdb[4] << 40) | ((uint64_t)cdb[5] << 32) |
         ((uint64_t)cdb[6] << 24) | ((uint64_t)cdb[7] << 16) |
         ((uint64_t)cdb[8] << 8) | (uint64_t)cdb[9];
}

uint32_t snowscsi_cdb_get_transfer_len16(const uint8_t *cdb) {
  return ((uint32_t)cdb[10] << 24) | ((uint32_t)cdb[11] << 16) |
         ((uint32_t)cdb[12] << 8) | (uint32_t)cdb[13];
}

const char *snowscsi_cdb_opcode_name(uint8_t opcode) {
  switch (opcode) {
  case SNOWSCSI_OP_TEST_UNIT_READY:
    return "TEST_UNIT_READY";
  case SNOWSCSI_OP_REQUEST_SENSE:
    return "REQUEST_SENSE";
  case SNOWSCSI_OP_READ_6:
    return "READ_6";
  case SNOWSCSI_OP_WRITE_6:
    return "WRITE_6";
  case SNOWSCSI_OP_INQUIRY:
    return "INQUIRY";
  case SNOWSCSI_OP_READ_CAPACITY_10:
    return "READ_CAPACITY_10";
  case SNOWSCSI_OP_READ_10:
    return "READ_10";
  case SNOWSCSI_OP_WRITE_10:
    return "WRITE_10";
  case SNOWSCSI_OP_READ_16:
    return "READ_16";
  case SNOWSCSI_OP_WRITE_16:
    return "WRITE_16";
  case SNOWSCSI_OP_SERVICE_ACTION_IN:
    return "SERVICE_ACTION_IN";
  case SNOWSCSI_OP_READ_12:
    return "READ_12";
  case SNOWSCSI_OP_WRITE_12:
    return "WRITE_12";
  case SNOWSCSI_OP_MODE_SENSE_6:
    return "MODE_SENSE_6";
  case SNOWSCSI_OP_MODE_SENSE_10:
    return "MODE_SENSE_10";
  case SNOWSCSI_OP_MODE_SELECT_6:
    return "MODE_SELECT_6";
  case SNOWSCSI_OP_MODE_SELECT_10:
    return "MODE_SELECT_10";
  case SNOWSCSI_OP_SYNCHRONIZE_CACHE_10:
    return "SYNCHRONIZE_CACHE_10";
  case SNOWSCSI_OP_SEND_DIAGNOSTIC:
    return "SEND_DIAGNOSTIC";
  case SNOWSCSI_OP_RECEIVE_DIAGNOSTIC:
    return "RECEIVE_DIAGNOSTIC";
  case SNOWSCSI_OP_REPORT_LUNS:
    return "REPORT_LUNS";
  case SNOWSCSI_OP_PREVENT_ALLOW:
    return "PREVENT_ALLOW";
  case SNOWSCSI_OP_START_STOP_UNIT:
    return "START_STOP_UNIT";
  default:
    return "UNKNOWN";
  }
}
