# NoteHub (evaluation fixture)

A small, intentionally vulnerable multi-language app used only to measure CodeWarden's precision
and recall on code other than the hackathon sample. It mixes Express, Flask, React and PostgreSQL,
and contains deliberately *safe* look-alike code (decoys) to measure false positives.
Never deploy it. All credential-like values are fabricated.
