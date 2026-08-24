"""Fixed deterministic worker: extraction only, no inference or instruction execution."""
import json
import re
import sys


def main():
    request = json.loads(sys.stdin.buffer.read(1048704))
    if set(request) != {'text'} or not isinstance(request['text'], str):
        raise ValueError('invalid reader input')
    paragraphs = [part.strip() for part in re.split(r'\n\s*\n', request['text']) if part.strip()]
    if len(paragraphs) > 1024:
        raise ValueError('too many paragraphs')
    sys.stdout.buffer.write(
        json.dumps({'paragraphs': paragraphs, 'facts': []}, ensure_ascii=False).encode('utf-8')
    )


if __name__ == '__main__':
    main()

