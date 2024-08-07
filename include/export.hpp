#pragma once

#ifdef SPANK_OLM_STATIC_DEFINE
#  define SPANK_OLM_EXPORT
#  define SPANK_OLM_NO_EXPORT
#else
#  ifndef SPANK_OLM_EXPORT
#    ifdef SPANK_olm_EXPORTS
        /* We are building this library */
#      define SPANK_OLM_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define SPANK_OLM_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef SPANK_OLM_NO_EXPORT
#    define SPANK_OLM_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef SPANK_OLM_DEPRECATED
#  define SPANK_OLM_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef SPANK_OLM_DEPRECATED_EXPORT
#  define SPANK_OLM_DEPRECATED_EXPORT SPANK_OLM_EXPORT SPANK_OLM_DEPRECATED
#endif

#ifndef SPANK_OLM_DEPRECATED_NO_EXPORT
#  define SPANK_OLM_DEPRECATED_NO_EXPORT SPANK_OLM_NO_EXPORT SPANK_OLM_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef SPANK_OLM_NO_DEPRECATED
#    define SPANK_OLM_NO_DEPRECATED
#  endif
#endif

