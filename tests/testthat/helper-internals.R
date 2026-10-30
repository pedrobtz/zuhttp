# Internal functions and routines, reached the way the rest of this suite
# reaches them, and defined once so every test can use them in any order
# (devtools::test(shuffle = TRUE)).
resolved          <- function(req, client) zuhttp:::resolve_request(req, client)
client_pool       <- function(...) zuhttp:::client_pool(...)
pool_valid        <- function(ptr) .Call(zuhttp:::C_zu_pool_valid, ptr)
parse_retry_after <- function(...) zuhttp:::parse_retry_after(...)
backoff_delay     <- function(...) zuhttp:::backoff_delay(...)
retry_sleep       <- function(...) zuhttp:::retry_sleep(...)
zu_defaults       <- function(...) zuhttp:::zu_defaults(...)
zu_stop           <- function(...) zuhttp:::zu_stop(...)

# The dynamic symbols a shared object exports, for test-abi.R (D-66).
exported_symbols <- function(dll) {
  if (.Platform$OS.type == "windows") {
    # A DLL's exports are its export table, which objdump prints between the
    # "[Ordinal/Name Pointer] Table" header and the next blank line, one entry
    # per line that starts with an "[ordinal]". Newer binutils add a column
    # header and a hint ("[   0] +base[   1]  0000 R_init_zuhttp"): the name is
    # the last field either way.
    objdump <- Sys.which("objdump")
    skip_if(objdump == "", "objdump is not on the PATH")
    out <- system2(objdump, c("-p", shQuote(dll)), stdout = TRUE)
    start <- grep("[Ordinal/Name Pointer] Table", out, fixed = TRUE)
    skip_if(length(start) == 0, "objdump printed no export table")
    rest <- out[seq(start[[1]] + 1, length(out))]
    rest <- rest[seq_len(match(TRUE, !nzchar(trimws(rest)), length(rest) + 1) - 1)]
    rest <- trimws(rest[grepl("^\\s*\\[", rest)])
    return(sub("^.*\\s", "", rest))
  }
  nm <- Sys.which("nm")
  skip_if(nm == "", "nm is not on the PATH")
  args <- if (Sys.info()[["sysname"]] == "Darwin") c("-gU") else c("-D", "--defined-only")
  out <- system2(nm, c(args, shQuote(dll)), stdout = TRUE)
  syms <- sub("^.*\\s", "", out[grepl("\\s[TDBRSV]\\s", out)])
  # Mach-O prefixes C symbols with an underscore.
  sub("^_", "", syms)
}
