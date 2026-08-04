fn main() {
    clap::Command::new("snowscsi")
        .about("SnowDrive iSCSI target")
        .subcommand(
            clap::Command::new("serve")
                .about("Start iSCSI target server")
                .arg(
                    clap::Arg::new("block")
                        .long("block")
                        .value_name("PATH|ram=SIZE")
                        .help("Block device: file path or ram=<bytes>")
                        .num_args(1..),
                )
                .arg(
                    clap::Arg::new("iscsi")
                        .long("iscsi")
                        .value_name("ADDR:PORT")
                        .help("iSCSI listen address")
                        .default_value("0.0.0.0:3260"),
                )
                .arg(
                    clap::Arg::new("verbose")
                        .long("verbose")
                        .short('v')
                        .action(clap::ArgAction::SetTrue)
                        .help("Verbose output"),
                )
                .arg(
                    clap::Arg::new("work-buf-size")
                        .long("work-buf-size")
                        .value_name("BYTES")
                        .help("Work buffer size"),
                ),
        )
        .get_matches();

    println!("snowscsi: not yet implemented");
}
