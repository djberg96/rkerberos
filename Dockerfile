# Use the official Ruby image with build tools
FROM ruby:3.2

# Install MIT Kerberos development libraries
RUN apt-get update && \
    apt-get install -y libkrb5-dev krb5-user && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy the Gem and extension files
COPY . /app

# Install dependencies
RUN bundle install

# Default command
CMD ["irb"]
