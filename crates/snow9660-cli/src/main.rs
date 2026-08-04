fn main() {
    clap::Command::new("snow9660")
        .about("SnowDrive ISO9660 filesystem tools")
        .subcommand(
            clap::Command::new("list")
                .about("List ISO directory tree")
                .arg(
                    clap::Arg::new("image")
                        .value_name("IMAGE")
                        .help("ISO image file")
                        .required(true),
                ),
        )
        .get_matches();

    println!("snow9660: not yet implemented");
}
