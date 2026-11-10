# Reference application/x-www-form-urlencoded decoder for test-request.R
# (#243). stdin: a JSON array of form bodies. stdout: a JSON array with,
# for each body, its [name, value] pairs as urllib.parse.parse_qsl() reads
# them, strictly and keeping empty values. "+" decodes to a space here, as
# the form encoding says, so an encoder that left "+" bare would not
# round-trip.
import json
import sys
from urllib.parse import parse_qsl

bodies = json.loads(sys.stdin.buffer.read().decode("utf-8"))
out = []
for b in bodies:
    if b == "":
        out.append([])
        continue
    pairs = parse_qsl(b, keep_blank_values=True, strict_parsing=True,
                      encoding="utf-8", errors="strict")
    out.append([[k, v] for k, v in pairs])
sys.stdout.write(json.dumps(out))
