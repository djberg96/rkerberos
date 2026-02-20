require 'rake'
begin
  require 'rspec/core/rake_task'
rescue LoadError
  # RSpec not available
end
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

# RSpec tasks
desc 'Run all specs'
RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = 'spec/**/*_spec.rb'
end

# Run specs inside the project container using podman-compose (or docker-compose)
namespace :spec do
  desc 'Build test image and run RSpec inside container (podman-compose or docker-compose)'
  task :compose do
    compose = `which podman-compose`.strip
    compose = 'docker-compose' if compose.empty?

    puts "Using #{compose} to run containerized specs..."

    FileUtils.rm_rf('Gemfile.lock')
    begin
      sh "#{compose} build --no-cache rkerberos-test"
      sh "#{compose} run --rm rkerberos-test"
    ensure
      sh "#{compose} down -v"
    end
  end
end

# Clean up afterwards
Rake::Task[:spec].enhance do
  Rake::Task[:clean].invoke
end

task :default => [:compile, :spec]
