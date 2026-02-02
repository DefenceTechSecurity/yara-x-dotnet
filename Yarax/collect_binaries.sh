#!/bin/bash
set -e

TargetTag="v1.12.0"

# local runs: avoid downloading when we have at least one binary.
if [ -f "capi-x86_64-pc-windows-msvc/yara_x_capi.dll" ]; then
	echo "Binaries already present, skipping download."
	exit 0
fi

wget "https://github.com/DefenceTechSecurity/yara-x-dotnet-native/releases/download/$TargetTag/capi-x86_64-unknown-linux-gnu.zip"
wget "https://github.com/DefenceTechSecurity/yara-x-dotnet-native/releases/download/$TargetTag/capi-x86_64-pc-windows-msvc.zip"
wget "https://github.com/DefenceTechSecurity/yara-x-dotnet-native/releases/download/$TargetTag/capi-x86_64-apple-darwin.zip"
wget "https://github.com/DefenceTechSecurity/yara-x-dotnet-native/releases/download/$TargetTag/capi-aarch64-unknown-linux-gnu.zip"
wget "https://github.com/DefenceTechSecurity/yara-x-dotnet-native/releases/download/$TargetTag/capi-aarch64-apple-darwin.zip"

unzip capi-x86_64-unknown-linux-gnu.zip -d capi-x86_64-unknown-linux-gnu/
unzip capi-x86_64-pc-windows-msvc.zip -d capi-x86_64-pc-windows-msvc/
unzip capi-x86_64-apple-darwin.zip -d capi-x86_64-apple-darwin/
unzip capi-aarch64-unknown-linux-gnu.zip -d capi-aarch64-unknown-linux-gnu/
unzip capi-aarch64-apple-darwin.zip -d capi-aarch64-apple-darwin/

check_binary() {
	local dir="$1"
	local binary_name="$2"
	if [ ! -f "$dir/$binary_name" ]; then
		echo "Error: $binary_name not found in $dir"
		exit 1
	fi
}

check_binary "capi-x86_64-unknown-linux-gnu" "libyara_x_capi.so"
check_binary "capi-x86_64-pc-windows-msvc" "yara_x_capi.dll"
check_binary "capi-x86_64-apple-darwin" "libyara_x_capi.dylib"
check_binary "capi-aarch64-unknown-linux-gnu" "libyara_x_capi.so"
check_binary "capi-aarch64-apple-darwin" "libyara_x_capi.dylib"

rm *.zip