add_library(libsnowscsi STATIC
    snowscsi.c
    scsi.c
    device.c
    backend_ram.c
    backend_file.c
    block.c
    iscsi_pdu.c
    iscsi_target.c
    transport_bsd.c
)

target_include_directories(libsnowscsi
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(libsnowscsi PUBLIC snowcommon)

set_target_properties(libsnowscsi PROPERTIES OUTPUT_NAME snowscsi)
