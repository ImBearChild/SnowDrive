# SnowSCSI CLI
add_executable(snowscsi snowscsi_main.c)
target_link_libraries(snowscsi PRIVATE libsnowscsi)

# Snow9660 CLI
add_executable(snow9660 snow9660_main.c)
target_link_libraries(snow9660 PRIVATE libsnow9660)
