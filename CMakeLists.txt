cmake_minimum_required(VERSION 3.14)


#-----------------------------------------------------------------------
project(basePro)
set(TARGET_EXE ${PROJECT_NAME})
message("Cmake pro: " ${TARGET_EXE})

# add_subdirectory(base_fs)
# add_subdirectory(base)
# add_subdirectory(base_ll)
# add_subdirectory(test_ll)
add_subdirectory(test)
#-----------------------------------------------------------------------

