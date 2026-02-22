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

# Run specs inside the project container using podman-compose (or docker-compose).

# Helper that makes sure the container engine is reachable before we hand the
# work off to compose.  If there’s no daemon, the error message from the
# compose script is long and hard to interpret; we check explicitly and abort
# early with something friendly.
def check_container_daemon!(compose_cmd)
  # podman-compose, docker-compose and `docker compose` all talk to a daemon
  # through the appropriate CLI.  Rather than attempt to parse the command we
  # just try the underlying engine directly.
  engine = compose_cmd.start_with?('podman') ? 'podman' : 'docker'

  # run the command once and grab any diagnostic output
  output = `#{engine} info 2>&1`
  return if $?.success?

  # if the user has a weird DOCKER_HOST we might still be able to reach the
  # daemon on the default socket; try that before bailing out.
  if engine == 'docker'
    env = { 'DOCKER_HOST' => 'unix:///var/run/docker.sock' }
    if system(env, "#{engine} info > /dev/null 2>&1")
      puts "#{engine.capitalize} seems reachable via default socket; resetting DOCKER_HOST."
      ENV['DOCKER_HOST'] = env['DOCKER_HOST']
      return
    end
  end

  # otherwise fail with useful hints
  hint = if engine == 'docker'
           "ensure the daemon is running (`systemctl status docker`), " \
           "you have permission to access its socket (add yourself to the `docker` group), " \
           "and that DOCKER_HOST/contexts are configured correctly."
         else
           "ensure the podman service is running and accessible."
         end
  abort "#{engine.capitalize} daemon check failed:\n#{output.strip}\n#{hint}"
end

# helper that bootstraps a python virtualenv with docker-compose installed
# only needed when we're about to invoke the legacy "docker-compose" script; pods
# and the newer "docker compose" binary ship with the docker engine and don't need it.
def ensure_docker_compose_venv
  # allow users to disable the auto‑creation by setting the variable to
  # "false"/"0"; anything else (or unset) means we *do* prepare the venv.
  if ENV.key?('COMPOSE_WITH_PYTHON') &&
     %w[false 0].include?(ENV['COMPOSE_WITH_PYTHON'].downcase)
    puts 'skipping python virtualenv for docker-compose (COMPOSE_WITH_PYTHON set)'
    return
  end

  # if the user already has a working docker-compose executable in the
  # environment then there's no need for us to create a venv at all.  this
  # avoids the Ubuntu python3-venv problem when global docker-compose is
  # installed via apt.
  if system('which docker-compose > /dev/null 2>&1')
    puts 'docker-compose already on PATH, skipping virtualenv'
    return
  end

  return if File.exist?('.venv/bin/python')

  puts 'creating python virtualenv for docker-compose…'
  unless system('python3 -m venv .venv')
    abort <<~MSG
      failed to create virtualenv; make sure python3-venv is installed.
      On Debian/Ubuntu: apt install python3-venv
    MSG
  end

  sh '. .venv/bin/activate && pip install --upgrade pip && pip install docker-compose'
end

namespace :spec do
  desc 'Build test image and run RSpec inside container (podman-compose or docker-compose)'
  task :compose, [:fast] do |t, args|
    # allow either positional or named argument (e.g. "fast=true")
    fast = args[:fast]
    if fast && fast.include?("=")
      k,v = fast.split("=",2)
      fast = v if k == 'fast'
    end
    fast = true if fast == 'true'

    compose = `which podman-compose`.strip
    compose = 'docker-compose' if compose.empty?

    # if we're invoking the python-based docker-compose script, make sure the
    # virtualenv exists and install the tool there. only prefix the command with
    # the activation step when a venv has actually been prepared; if we skipped
    # creation because a system binary was available, don’t touch the command.
    if compose == 'docker-compose'
      ensure_docker_compose_venv
      if File.exist?('.venv/bin/activate')
        compose = ". .venv/bin/activate && #{compose}"
      end
    end

    if fast
      puts "Using #{compose} to run containerized specs (fast)..."
    else
      puts "Using #{compose} to run containerized specs..."
    end

    # ensure that whatever engine we're about to talk to is actually running;
    # docker-compose/podman-compose don't give the cleanest error message when
    # the daemon isn't there, so do a simple probe first.
    check_container_daemon!(compose)

    FileUtils.rm_rf('Gemfile.lock')
    begin
      sh "#{compose} build --no-cache rkerberos-test" unless fast
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
