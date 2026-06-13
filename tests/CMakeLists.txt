include(FetchContent)

FetchContent_Declare(
    ThrowTheSwitch_Unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG v2.6.1
)
FetchContent_MakeAvailable(ThrowTheSwitch_Unity)

add_executable(test_skeleton test_skeleton.c)
target_link_libraries(test_skeleton PRIVATE libsnowscsi libsnow9660 unity)
add_test(NAME skeleton COMMAND test_skeleton)

add_executable(test_block test_block.c)
target_link_libraries(test_block PRIVATE libsnowscsi unity)
add_test(NAME block COMMAND test_block)

add_executable(test_iscsi_pdu test_iscsi_pdu.c)
target_link_libraries(test_iscsi_pdu PRIVATE libsnowscsi unity)
add_test(NAME iscsi_pdu COMMAND test_iscsi_pdu)

add_executable(test_iscsi_target test_iscsi_target.c)
target_link_libraries(test_iscsi_target PRIVATE libsnowscsi unity)
add_test(NAME iscsi_target COMMAND test_iscsi_target)

