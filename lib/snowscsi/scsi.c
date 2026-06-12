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

uint32_t snowscsi_cdb_get_lba10(const uint8_t *cdb) {
  return ((uint32_t)cdb[2] << 24) | ((uint32_t)cdb[3] << 16) |
         ((uint32_t)cdb[4] << 8) | ((uint32_t)cdb[5]);
}

uint16_t snowscsi_cdb_get_transfer_len10(const uint8_t *cdb) {
  return ((uint16_t)cdb[7] << 8) | ((uint16_t)cdb[8]);
}
