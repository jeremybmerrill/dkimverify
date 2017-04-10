dkimverify
==========

a gem for verifying DKIM signatures in Ruby

this gem does not sign mail messages (but a PR to enable it would likely be accepted, I just have no use for it.)

I'm pretty sure this actually works and I'm using it in production.

how to use
-----------
````Dkim::Verifier.new(eml_filepath).verify!````

the `verify!` method will return:

- `true` if the signature verifies
- `false` if no signature is present, and,
- raise `Dkim::DkimError` (or a child error) if the signature is present but does not verify.

with a debt of gratitude to:
----------------------------

  - [pydkim](https://github.com/ghewgill/pydkim) by @ghewgill which I used as a more-or-less literal source of translation
  - [carsonreinke's fork of the jhawthorne's dkim gem](https://github.com/carsonreinke/dkim/tree/feature_verification) which I wish I had found before I started this.
  - [rfc6376 authors](https://tools.ietf.org/html/rfc6376)

not yet implemented
-------------------
checking expiration dates (x=, t=)
accounting for length limits (l= tag)
tests (which I really ought to add)
checking multiple dkim signature header lines (probably easy)

by
--

Jeremy B. Merrill
The New York Times
April 2017
