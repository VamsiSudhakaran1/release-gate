"""analysis-agent — the cache layer that sits behind the same service.

This file is the OTHER half of the demo: the look-alike that a name-matching
scanner reports as a confirmed remote-code-execution HIGH, and that release-gate
deliberately does not.

`pickle.loads(payload)` is a genuinely dangerous *shape*, and we do report it —
as a MEDIUM that says "origin unknown, confirm the source". What we refuse to do
is assert *confirmed RCE*, because nothing here proves `payload` is attacker
controlled. It is a function parameter; its value comes from the caller, which
this file cannot see. In AutoGPT the identically-named variable held the cache's
own HMAC-signed bytes, and calling that a confirmed vulnerability is how a report
gets dismissed by the maintainer who knows better.

The rule the engine applies: a variable's NAME is never evidence. A HIGH requires
a traced origin we can cite by line number — see `vulnerable/agent.py`, where the
value is traced to the model call on line 17.
"""
import pickle
from pathlib import Path


def load_cached_frame(payload: bytes):
    # `payload` merely *sounds* external. Reported MEDIUM / inferred:
    #   `payload` -> pickle.loads() (L26) — origin unknown (name suggests external input)
    return pickle.loads(payload)


def save_cached_frame(path: Path, blob: bytes) -> None:
    path.write_bytes(blob)
