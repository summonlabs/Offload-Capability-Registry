# First-party warning configuration. Flags are PRIVATE so they never leak into
# downstream consumers of the exported package.
function(ocreg_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4 /WX /permissive- /utf-8 /EHsc /Zc:__cplusplus /Zc:preprocessor
      /wd4127)  # conditional expression is constant (used by static_assert guards)
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    if(OCREG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    else()
      target_compile_options(${target} PRIVATE /WX-)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
      -Wold-style-cast -Wcast-qual -Wnon-virtual-dtor -Woverloaded-virtual
      -Wdouble-promotion -Wformat=2)
    if(OCREG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()
