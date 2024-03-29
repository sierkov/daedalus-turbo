if (WIN32)
    add_custom_target(
        ui
        COMMAND npm i
        COMMAND npm run pkg-build-win
        COMMAND npx shx mv dt-ui-win32-x64 bin
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ui
    )
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/ui/bin/ DESTINATION bin)
endif()