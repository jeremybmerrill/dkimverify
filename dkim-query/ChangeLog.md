### 0.2.6 / 2016-08-3

* Fixed a typo in the parser rules.

### 0.2.5 / 2016-06-17

* Added `mandrill` and `google` to the list of default DKIM selectors.

### 0.2.4 / 2015-08-13

* Fixed a bug where the queried host has no TLD (ex: `test`).

### 0.2.3 / 2015-07-22

* Fixed a typo in the `dkim-query` util.
* Convert all text into Strings.
* Convert `t=y` or `t=s` values to Symbols.

### 0.2.2 / 2015-07-04

* Fixed {DKIM::Query::MalformedKey#to_s}.

### 0.2.1 / 2015-07-01

* Initial release.
