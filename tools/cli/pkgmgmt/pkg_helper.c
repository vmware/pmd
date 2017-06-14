#include "includes.h"

char*
pkg_get_updateinfo_type(
    int nType
    )
{
    char* pszType = "Unknown";

    switch(nType)
    {
        case UPDATE_SECURITY:
            pszType = "Security";
            break;
        case UPDATE_BUGFIX:
            pszType = "Bugfix";
            break;
        case UPDATE_ENHANCEMENT:
            pszType = "Enhancement";
            break;
    }

    return pszType;
}
