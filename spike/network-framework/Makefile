# Deployment target 11.0: older than any macOS CRAN builds for, so a missing
# availability guard is a hard error here, as it would be a NOTE on CRAN.
CFLAGS = -std=c99 -O1 -g -fblocks -mmacosx-version-min=11.0 \
         -Wall -Wextra -Wpedantic -Wdeprecated-declarations \
         -Wunguarded-availability -Werror
nw_probe: nw_probe.c
	$(CC) $(CFLAGS) -o $@ $< -framework Network -framework Security -framework CoreFoundation
clean:
	rm -rf nw_probe nw_probe.dSYM
