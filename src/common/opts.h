/* Shared command-line helper: accept option values attached or separated.
 *
 * getopt(3) lets a caller write either "-W1" or "-W 1"; the hand-rolled
 * parsers in the tools should not be stricter than that. Usage:
 *
 *     const char *v;
 *     if ((v = nt_opt_value(arg, 'W', &i, argc, argv)) != NULL)
 *         timeout_ms = strtol(v, NULL, 10);
 */
#ifndef NT_OPTS_H
#define NT_OPTS_H

/* Return the value for short option `o` in `arg`. "-W1" yields "1"; "-W" yields
 * the next argv element and advances *i. Returns NULL if `arg` is not option
 * `o` or a separated value is missing. */
static inline const char *nt_opt_value(const char *arg, char o, int *i, int argc, char **argv)
{
    if (arg == NULL || arg[0] != '-' || arg[1] != o)
        return NULL;
    if (arg[2] != '\0')
        return arg + 2;
    if (*i + 1 >= argc)
        return NULL;
    return argv[++(*i)];
}

#endif /* NT_OPTS_H */
