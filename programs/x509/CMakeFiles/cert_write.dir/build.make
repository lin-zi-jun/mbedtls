# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jordan/mbedtls

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jordan/mbedtls

# Include any dependencies generated for this target.
include programs/x509/CMakeFiles/cert_write.dir/depend.make

# Include the progress variables for this target.
include programs/x509/CMakeFiles/cert_write.dir/progress.make

# Include the compile flags for this target's objects.
include programs/x509/CMakeFiles/cert_write.dir/flags.make

programs/x509/CMakeFiles/cert_write.dir/cert_write.c.o: programs/x509/CMakeFiles/cert_write.dir/flags.make
programs/x509/CMakeFiles/cert_write.dir/cert_write.c.o: programs/x509/cert_write.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jordan/mbedtls/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object programs/x509/CMakeFiles/cert_write.dir/cert_write.c.o"
	cd /home/jordan/mbedtls/programs/x509 && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/cert_write.dir/cert_write.c.o   -c /home/jordan/mbedtls/programs/x509/cert_write.c

programs/x509/CMakeFiles/cert_write.dir/cert_write.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/cert_write.dir/cert_write.c.i"
	cd /home/jordan/mbedtls/programs/x509 && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jordan/mbedtls/programs/x509/cert_write.c > CMakeFiles/cert_write.dir/cert_write.c.i

programs/x509/CMakeFiles/cert_write.dir/cert_write.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/cert_write.dir/cert_write.c.s"
	cd /home/jordan/mbedtls/programs/x509 && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jordan/mbedtls/programs/x509/cert_write.c -o CMakeFiles/cert_write.dir/cert_write.c.s

# Object files for target cert_write
cert_write_OBJECTS = \
"CMakeFiles/cert_write.dir/cert_write.c.o"

# External object files for target cert_write
cert_write_EXTERNAL_OBJECTS =

programs/x509/cert_write: programs/x509/CMakeFiles/cert_write.dir/cert_write.c.o
programs/x509/cert_write: programs/x509/CMakeFiles/cert_write.dir/build.make
programs/x509/cert_write: library/libmbedtls.so.2.4.2
programs/x509/cert_write: library/libmbedx509.so.2.4.2
programs/x509/cert_write: library/libmbedcrypto.so.2.4.2
programs/x509/cert_write: programs/x509/CMakeFiles/cert_write.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jordan/mbedtls/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable cert_write"
	cd /home/jordan/mbedtls/programs/x509 && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cert_write.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
programs/x509/CMakeFiles/cert_write.dir/build: programs/x509/cert_write

.PHONY : programs/x509/CMakeFiles/cert_write.dir/build

programs/x509/CMakeFiles/cert_write.dir/clean:
	cd /home/jordan/mbedtls/programs/x509 && $(CMAKE_COMMAND) -P CMakeFiles/cert_write.dir/cmake_clean.cmake
.PHONY : programs/x509/CMakeFiles/cert_write.dir/clean

programs/x509/CMakeFiles/cert_write.dir/depend:
	cd /home/jordan/mbedtls && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jordan/mbedtls /home/jordan/mbedtls/programs/x509 /home/jordan/mbedtls /home/jordan/mbedtls/programs/x509 /home/jordan/mbedtls/programs/x509/CMakeFiles/cert_write.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : programs/x509/CMakeFiles/cert_write.dir/depend

