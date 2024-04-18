cmake_minimum_required(VERSION 3.28)

project(ut2004-key-generator)

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE Bcrypt)

set_target_properties(${PROJECT_NAME}
    PROPERTIES
        CXX_STANDARD_REQUIRED ON
        CXX_STANDARD 23)
