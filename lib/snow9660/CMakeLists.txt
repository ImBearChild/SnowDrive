add_library(libsnow9660 STATIC
    snow9660.c
)

target_include_directories(libsnow9660
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(libsnow9660 PUBLIC snowcommon)

set_target_properties(libsnow9660 PROPERTIES OUTPUT_NAME snow9660)
