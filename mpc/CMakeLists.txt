cmake_minimum_required(VERSION 3.16)
project(mpc LANGUAGES CXX)

# MOTION is built as C++20 (and its headers use C++20 features).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
          "Choose the type of build, options are: None Debug Release"
          FORCE)
endif (NOT CMAKE_BUILD_TYPE)

set(MOTION_Boost_VERSION "1.75.0")
list(APPEND MOTION_Boost_COMPONENTS
        context
        fiber
        filesystem
        json
        log
        log_setup
        program_options
        system
        thread
        atomic
        chrono
        date_time)

# Prefer building Boost locally to ensure matching static ABI with libmotion.a
# If you want to use system boost, you can set -DMPC_USE_SYSTEM_BOOST=ON
option(MPC_USE_SYSTEM_BOOST "Use system boost" OFF)

if(MPC_USE_SYSTEM_BOOST)
  set(Boost_USE_STATIC_LIBS ON)
  find_package(Boost QUIET ${MOTION_Boost_VERSION}
          COMPONENTS
          ${MOTION_Boost_COMPONENTS})

  # Check if all required Boost component targets exist.
  set(ALL_BOOST_COMPONENTS_FOUND TRUE)
  foreach(comp ${MOTION_Boost_COMPONENTS})
    if(NOT TARGET Boost::${comp})
      set(ALL_BOOST_COMPONENTS_FOUND FALSE)
      break()
    endif()
  endforeach()

  if(NOT Boost_FOUND OR NOT ALL_BOOST_COMPONENTS_FOUND)
    message(STATUS "System boost not found or incomplete, building locally.")
    include(cmake/BuildBoostLocally.cmake)
  endif()
else()
  include(cmake/BuildBoostLocally.cmake)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)

# Define the motion library (prebuilt).
# When you move this folder, you should update these paths or use a proper find_package mechanism.
add_library(motion_prebuilt STATIC IMPORTED GLOBAL)
set_target_properties(motion_prebuilt PROPERTIES
  IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/motion/lib/libmotion.a"
)

target_include_directories(motion_prebuilt INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/motion/include"
)

# ENSURE Boost.Log uses STATIC linkage ABI, as libmotion.a was built this way.
# We DO NOT define BOOST_LOG_DYN_LINK here.

add_executable(mpc main.cpp)
target_link_libraries(mpc PRIVATE
  motion_prebuilt
  Boost::log_setup
  Boost::log
  Boost::program_options
  Boost::fiber
  Boost::context
  Boost::filesystem
  Boost::json
  Boost::thread
  Boost::system
  Boost::atomic
  Boost::chrono
  Boost::date_time
  OpenSSL::Crypto
  OpenMP::OpenMP_CXX
)
