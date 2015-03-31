add_library(secrets SHARED cdecode.c cencode.c secrets.c)
#set_target_properties(secrets_static PROPERTIES OUTPUT_NAME secrets)

add_library(secrets_preload SHARED cdecode.c cencode.c secrets.c preload.c)
target_link_libraries(secrets dl mcrypt keyutils)
target_link_libraries(secrets_preload mcrypt keyutils dl)

add_executable(secrets_example OUTPUT_NAME secrets secrets_example.c)
target_link_libraries(secrets_example LINK_PUBLIC secrets dl keyutils mcrypt)
