use snowdrive::udf_void::{compute_layout, gen_sector};
use std::fs::File;
use std::io::Write;

fn main() {
    let cap = 20480u32;
    let layout = compute_layout(cap, "REF").unwrap();
    let mut out = vec![0u8; cap as usize * 2048];
    for lba in 0..cap {
        let mut s = [0u8; 2048];
        if gen_sector(&layout, lba, &mut s) {
            out[lba as usize * 2048..(lba as usize + 1) * 2048].copy_from_slice(&s);
        }
    }
    let mut f = File::create("/tmp/opencode/snow.udf").unwrap();
    f.write_all(&out).unwrap();
    eprintln!(
        "snow image: vds={} lvid={} part={} anchor2={} anchor3={} reserve_vds={} sbd={} free_from={} root_icb={} root_dir={}",
        layout.vds_lba,
        layout.lvid_lba,
        layout.partition_lba,
        layout.anchor2_lba,
        layout.anchor3_lba,
        layout.reserve_vds_lba,
        layout.sbd_lba,
        layout.free_from_block,
        layout.root_icb_lba,
        layout.root_dir_lba
    );
}
