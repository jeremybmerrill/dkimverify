dkimverify
==========

a gem for verifying DKIM signatures in Ruby

this gem does not sign mail messages (but a PR to enable it would likely be accepted, I just have no use for it.)

**this gem doesn't work right yet!!!**

how to use
-----------
````Dkim::Verifier.new(eml_filepath).verify!````

the `verify!` method will return:

- `true` if the signature verifies
- `false` if no signature is present, and,
- raise `Dkim::DkimError` (or a child error) if the signature is present but does not verify.

loading emails from a string is not yet implemented, but would be really easy (send me a PR!)




with a debt of gratitude to:
----------------------------

  - [pydkim](https://github.com/ghewgill/pydkim) by @ghewgill which I used as a reference implementation
  - [mail](https://github.com/mikel/mail) by @mikel
  - [carsonreinke's fork of the jhawthorne's dkim gem](https://github.com/carsonreinke/dkim/tree/feature_verification) which I wish I had found before I started this.
  - [rfc6376 authors](https://tools.ietf.org/html/rfc6376)

not yet implemented
-------------------
checking expiration dates (x=, t=)
accounting for length limits (l= tag)
tests (which I really ought to add)
checking multiple dkim signature header lines (probably easy)
dealing with the "simple" canonicalization method (because I need to strip out the `mail` gem and instead write my own RFC822 parser that is better for maintaining the exact original string)

by
--

Jeremy B. Merrill  
The New York Times  
January 2017  
