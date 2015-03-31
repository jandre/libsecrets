include(LibFindMacros)


# Main include dir
find_path(LibMCrypt_INCLUDE_DIR
  NAMES mcrypt.h 
)

# Finally the library itself
find_library(LibMCrypt_LIBRARY
  NAMES libmcrypt
)

# Set the include dir variables and the libraries and let libfind_process do the rest.
# NOTE: Singular variables for this library, plural for libraries this this lib depends on.
set(LibMCrypt_PROCESS_INCLUDES LibMCrypt_INCLUDE_DIR)
set(LibMCrypt_PROCESS_LIBS LibMCrypt_LIBRARY)
libfind_process(LibMCrypt)
