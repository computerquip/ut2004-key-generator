cmake_minimum_required(VERSION 3.28)

project(ut2004-key-generator)

add_executable(${PROJECT_NAME} src/main.cpp)

if (WIN32)
    add_subdirectory(src/wil-1.0.240122.1)
    target_link_libraries(${PROJECT_NAME} PRIVATE Bcrypt WIL::WIL)
endif ()

set_target_properties(${PROJECT_NAME}
    PROPERTIES
        CXX_STANDARD_REQUIRED ON
        CXX_STANDARD 23)
