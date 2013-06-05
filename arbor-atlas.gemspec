# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'arbor/atlas/version'

Gem::Specification.new do |spec|
	spec.name          = "arbor-atlas"
	spec.version       = Arbor::Atlas::VERSION
	spec.authors       = ["chrislee35"]
	spec.email         = ["rubygems@chrislee.dhs.org"]
	spec.description   = %q{The ATLAS portal today is a public resource that delivers a sub-set of the intelligence derived from the ATLAS sensor network on host/port scanning activity, zero-day exploits and worm propagation, security events, vulnerability disclosures and dynamic botnet and phishing infrastructures.}
	spec.summary       = %q{A very thin wrapper around Arbor Atlas' web interface}
	spec.homepage      = "https://github.com/chrislee35/arbor-atlas"
	spec.license       = "MIT"

	spec.files         = `git ls-files`.split($/)
	spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
	spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
	spec.require_paths = ["lib"]

	spec.add_runtime_dependency "configparser", "~> 0.1.1"
	spec.add_runtime_dependency "json", ">= 1.4.3"
	spec.add_runtime_dependency "crack", ">= 0.3.2"
	spec.add_development_dependency "bundler", "~> 1.3"
	spec.add_development_dependency "rake"

	spec.signing_key   = "#{File.dirname(__FILE__)}/../gem-private_key.pem"
	spec.cert_chain    = ["#{File.dirname(__FILE__)}/../gem-public_cert.pem"]
end
