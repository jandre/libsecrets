include(LibFindMacros)


# Main include dir
find_path(LibKeyUtils_INCLUDE_DIR
  NAMES keyutils.h 
)

# Finally the library itself
find_library(LibKeyUtils_LIBRARY
  NAMES libkeyutils 
)

# Set the include dir variables and the libraries and let libfind_process do the rest.
# NOTE: Singular variables for this library, plural for libraries this this lib depends on.
set(LibKeyUtils_PROCESS_INCLUDES LibKeyUtils_INCLUDE_DIR)
set(LibKeyUtils_PROCESS_LIBS LibKeyUtils_LIBRARY)
libfind_process(LibKeyUtils)
