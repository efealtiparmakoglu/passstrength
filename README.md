# passstrength

**Offline password strength checker — coverage-based pattern detection, honest crack-time estimates, and a browser widget that never phones home. Zero dependencies.**

```
$ printf 'summer2024' | passstrength
██░░░░  WEAK
length      10 characters
model       ~3.54e+5 guesses (18.4 bits)

crack time at:
  online, throttled (100/hr):      3.5 hours
  online, unthrottled (10k/hr):    2.1 minutes
  offline, bcrypt (10k/s):         35 seconds
  offline, GPU vs fast hash:       instantly

patterns:
  [dictionary-sub] contains the common word "summer"
  [year] 2024 is a calendar year

warnings:
  ! shorter than 12 characters
  ! contains a word attackers try first
  ! contains a date or year — low entropy
  ! falls to a GPU rig within an hour
```

Most strength meters compute `length × log2(charset)` and call it a day —
which happily rates `aaaaaaaaaaaa` as strong. passstrength works the way
real crackers do: it finds the *patterns* (dictionary words, repeats,
keyboard walks, counting runs, years, dates), measures how much of the
password those cover, and charges the attacker only for what is left.

## Why passstrength

- **Coverage-based model.** Patterns carry spans; overlapping matches are
  merged; only uncovered characters cost full brute-force guesses. That
  single change is why `aaaaaaaaaaaa` scores 0 while
  `xK9!mQ2#Lv@Zp4` scores 4.
- **Time caps the rating.** A raw guess count flatters short passwords, so
  the score is also capped by how long the password survives a fast-hash
  GPU rig: `hunter2` drops from "4" to "weak" because it dies in seconds.
- **Four attack scenarios.** Throttled login, unthrottled login, bcrypt,
  and a fast hash on a GPU rig — a strong password against one is often
  weak against the other.
- **Leetspeak, keyboard walks and reversed runs** are all detected, with
  the matched span shown so you can see *what* the attacker exploits.
- **Nothing leaves the machine.** No network code anywhere; the widget is
  a static page importing the same scoring core.
- **The widget is the same code.** `scripts/build-widget.mjs` strips the
  TypeScript types with Node's built-in stripper and writes
  `public/scoring.js`; `npm test` builds it, so the browser bundle can
  never drift from the CLI.

## Usage

```sh
passstrength 'my password'        # argument (visible in shell history!)
printf 'secret\n' | passstrength  # stdin — preferred
passstrength --file creds.txt --json
node scripts/build-widget.mjs     # regenerate public/scoring.js
```

Then open `public/widget.html` in a browser for the live version.

## What this is not

Not a password manager and not a generator. Its word list is a small
embedded set of the most common passwords, so a password built from a
rare word it doesn't know (`hunter2` before you add it) can be
overrated — the time caps blunt that, but no offline estimator is
complete. Real defense is length: 16+ unrelated characters, unique per
site, stored in a manager.

## Development

```sh
npm test    # 14 tests + widget bundle build
```

## License

MIT — see [LICENSE](LICENSE).
