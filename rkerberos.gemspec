require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'rkerberos'
  spec.version    = '0.1.5'
  spec.authors    = ['Daniel Berger', 'Dominic Cleal', 'Simon Levermann']
  spec.license    = 'Artistic 2.0'
  spec.email      = ['djberg96@gmail.com', 'dominic@cleal.org', 'simon-rubygems@slevermann.de']
  spec.homepage   = 'http://github.com/domcleal/rkerberos'
  spec.summary    = 'A Ruby interface for the the Kerberos library'
  spec.test_files = Dir['spec/**/*_spec.rb']
  spec.extensions = ['ext/rkerberos/extconf.rb']
  spec.files      = `git ls-files`.split("\n").reject { |f| f.include?('git') }

  spec.extra_rdoc_files  = ['README.md', 'CHANGES', 'MANIFEST', 'LICENSE'] + Dir['ext/rkerberos/*.c']

  spec.add_dependency('rake-compiler')

  spec.add_development_dependency('rspec', '>= 3.0')
  spec.add_development_dependency('net-ldap')

  spec.description = <<-EOF
    The rkerberos library is an interface for the Kerberos 5 network
    authentication protocol. It wraps the Kerberos C API.
  EOF
end
