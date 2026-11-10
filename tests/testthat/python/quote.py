# Reference percent-encoder for test-request.R (#243).
# stdin: a JSON array of strings. stdout: a JSON array, each string encoded
# by urllib.parse.quote() with nothing marked safe, so only RFC 3986's
# unreserved set (ALPHA DIGIT - . _ ~) is left as is. UTF-8 throughout.
import json
import sys
from urllib.parse import quote

strings = json.loads(sys.stdin.buffer.read().decode("utf-8"))
out = [quote(s, safe="", encoding="utf-8", errors="strict") for s in strings]
sys.stdout.write(json.dumps(out))
