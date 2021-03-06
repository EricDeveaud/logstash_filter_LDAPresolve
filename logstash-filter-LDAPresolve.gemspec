Gem::Specification.new do |s|
  s.name = 'logstash-filter-LDAPresolve'
  s.version         = '0.1.2'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This filter adds infodrmation fields from LDAP server based on the provided uid."
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Eric Deveaud"]
  s.email = 'edeveaud@pasteur.fr'
  s.homepage = "http://projets.pasteur.fr"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", '>= 1.4.0', '< 2.0.0'
  s.add_runtime_dependency "jruby-ldap"
  s.add_development_dependency 'logstash-devutils'
end
