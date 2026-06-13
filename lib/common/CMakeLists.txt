add_library(snowcommon STATIC snowlog.c)

target_include_directories(snowcommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
