#!/bin/bash

# Test script for IronChat UI
echo "Testing IronChat UI functionality..."

# Set environment variables
export IRC_SERVER=127.0.0.1
export IRC_PORT=6697
export IRC_NICK=test_user
export IRC_NO_CERT_VERIFY=1
export IRC_CHANNELS=#testing

# Start the client and send some test commands
(
    sleep 2
    echo "Hello everyone, this is a test message!"
    sleep 1
    echo "/help"
    sleep 1
    echo "/list"
    sleep 1
    echo "/join #general"
    sleep 2
    echo "Hello #general!"
    sleep 1
    echo "/switch #testing"
    sleep 1
    echo "Back in #testing"
    sleep 1
    echo "/quit Testing complete"
) | timeout 20s cargo run --release