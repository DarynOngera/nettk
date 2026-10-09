#include "nettk.h"

const char *nt_status_str(nt_status s)
{
    switch (s) {
    case NT_OK:              return "NT_OK";
    case NT_ERR_TRUNCATED:   return "NT_ERR_TRUNCATED";
    case NT_ERR_MALFORMED:   return "NT_ERR_MALFORMED";
    case NT_ERR_UNSUPPORTED: return "NT_ERR_UNSUPPORTED";
    }
    return "NT_ERR_UNKNOWN";
}
