#!/usr/bin/env python3
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    print('usage: patch-nginx-stream.py <nginx.conf>', file=sys.stderr)
    sys.exit(2)

p = Path(sys.argv[1])
text = p.read_text(encoding='utf-8')
if re.search(r'^[ \t]*include[ \t]+\S*stream\.d/\*\.conf[ \t]*;', text, re.M):
    sys.exit(0)

existing = re.search(r'^[ \t]*stream[ \t]*\{[ \t]*$', text, re.M)
if existing:
    text = text[:existing.end()] + '\n    include stream.d/*.conf;' + text[existing.end():]
else:
    text = text.rstrip('\n') + '\n\nstream {\n    include stream.d/*.conf;\n}\n'
p.write_text(text, encoding='utf-8')
