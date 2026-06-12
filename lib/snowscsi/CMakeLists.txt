add_library(libsnowscsi STATIC
    snowscsi.c
)

target_include_directories(libsnowscsi
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

set_target_properties(libsnowscsi PROPERTIES OUTPUT_NAME snowscsi)
