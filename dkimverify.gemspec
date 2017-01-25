# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.name          = "dkimverify"
  gem.version       = '0.0.1'
  gem.authors       = ["Jeremy B. Merrill"]
  gem.license       = "MIT"
  gem.email         = ["jeremybmerrill@gmail.com"]
  gem.description   = %q{ A pure-Ruby library for validating/verifying DKIM signatures. }
  gem.summary       = %q{ A pure-Ruby library for validating/verifying DKIM signatures. }
  gem.homepage      = "https://github.com/jeremybmerrill/dkimverify"
  gem.files         = `git ls-files`.split($/)
  gem.require_paths = ["dkim-query"]
  gem.add_dependency "mail", "2.6.4"
  gem.add_dependency "parslet", "~> 1.6"
end
