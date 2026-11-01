"""Organizer-side exact flag validation; do not distribute the answer manifest."""
import argparse
import hmac
import json
from pathlib import Path


def check(answers, challenge, submitted):
    """Validate a platform submission; permit surrounding paste whitespace only."""
    return hmac.compare_digest(answers[challenge]['flag'].encode(), submitted.strip().encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--answers', type=Path, required=True)
    parser.add_argument('--challenge', choices=('easy', 'hard'), required=True)
    parser.add_argument('--flag', required=True)
    args = parser.parse_args()
    valid = check(json.loads(args.answers.read_text()), args.challenge, args.flag)
    print('Correct' if valid else 'Incorrect; review all challenge conditions and event-ID order.')
    raise SystemExit(0 if valid else 1)


if __name__ == '__main__':
    main()
