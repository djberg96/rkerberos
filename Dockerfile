# Dockerfile for rkerberos Ruby gem testing
FROM ruby:3.2

# Install MIT Kerberos development libraries and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libkrb5-dev krb5-user rake build-essential && \
    rm -rf /var/lib/apt/lists/*

# Set up a working directory
WORKDIR /app

# Copy the gemspec and Gemfile for dependency installation
COPY Gemfile rkerberos.gemspec ./

# Install gem dependencies
RUN bundle install

# Copy the rest of the code
COPY . .

# Default command: run tests
CMD ["rake", "test"]
