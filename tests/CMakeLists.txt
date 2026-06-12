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
