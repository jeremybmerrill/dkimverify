dkimverify
---------

a gem for verifying DKIM signatures in Ruby

this gem does not sign mail messages (but a PR to enable it would likely be accepted, I just have no use for it.)

with a debt of gratitude to:
============================

  - [pydkim](https://github.com/ghewgill/pydkim) by @ghewgill
  - [dkim-query](https://github.com/trailofbits/dkim-query) by @trailofbits (and included here in slightly-modified form)
  - [mail](https://github.com/mikel/mail) by @mikel
  - [carsonreinke's fork of the jhawthorne's dkim gem](https://github.com/carsonreinke/dkim/tree/feature_verification) which I wish I had found before I started this.
  - [rfc6376 authors](https://tools.ietf.org/html/rfc6376)

not yet implemented
====================
checking expiration dates (x=, t=)
accounting for length limits (l= tag)
tests (which I really ought to add)

by
==

Jeremy B. Merrill
The New York Times
January 2017
