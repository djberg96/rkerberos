require 'rake'
require 'rspec/core/rake_task'
require 'rake/extensiontask'
require 'rake/clean'
require 'rbconfig'
require 'rubygems/package'

# Windows one-click
require 'devkit' if RbConfig::CONFIG['host_os'] =~ /cygwin|mingw/i

Rake::ExtensionTask.new('rkerberos')

CLEAN.include(
  '**/*.gem',               # Gem files
  '**/*.rbc',               # Rubinius
  '**/*.o',                 # C object file
  '**/*.log',               # Ruby extension build log
  '**/Makefile',            # C Makefile
  '**/conftest.dSYM',       # OS X build directory
  '**/tmp',                 # Temp directory
  "**/*.#{RbConfig::CONFIG['DLEXT']}" # C shared object
)

desc 'Create a tarball of the source'
task :archive do
  spec = eval(IO.read('rkerberos.gemspec'))
  prefix = "rkerberos-#{spec.version}/"
  Dir['*.tar*'].each{ |f| File.delete(f) }
  sh "git archive --prefix=#{prefix} --format=tar HEAD > rkerberos-#{spec.version}.tar"
  sh "gzip rkerberos-#{spec.version}.tar"
end

namespace :gem do
  desc 'Delete any existing gem files in the project.'
  task :clean do
    Dir['*.gem'].each{ |f| File.delete(f) }
    rm_rf 'lib'
  end

  desc 'Create the gem'
  task :create => [:clean] do
    spec = eval(IO.read('rkerberos.gemspec'))
    Gem::Package.build(spec)
  end

  desc 'Install the gem'
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file}"
  end

  desc 'Create a binary gem'
  task :binary => [:clean, :compile] do
    spec = eval(IO.read('rkerberos.gemspec'))
    spec.platform = Gem::Platform::CURRENT
    spec.extensions = nil
    spec.files = spec.files.reject{ |f| f.include?('ext') }

    Gem::Builder.new(spec).build
  end
end

namespace :sample do
  desc "Run the sample configuration display program"
  task :config => [:compile] do
    sh "ruby -Ilib samples/sample_config_display.rb"
  end
end

task :default => ['test:all']
task :test => ['test:all']
RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = 'spec/**/*_spec.rb'
end

task :default => [:spec]
task :test => [:spec]

# Docker tasks
namespace :docker do
  desc 'Build the Docker image'
  task :build do
    sh 'docker-compose build'
  end

  desc 'Run tests in Docker container'
  task :test do
    sh 'docker-compose run --rm rkerberos bundle exec rake test:all'
  end

  desc 'Open a shell in the Docker container'
  task :shell do
    sh 'docker-compose run --rm rkerberos bash'
  end
end
