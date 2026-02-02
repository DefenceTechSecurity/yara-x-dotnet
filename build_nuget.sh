#/bin/bash

set -e

# Build the managed project and create a NuGet package
dotnet build ./Yarax.Managed/Yarax.Managed.csproj -c Release
dotnet pack ./Yarax.Managed/Yarax.Managed.csproj -c Release -o ./nupkgs

# Build the project with all the native dependencies
pushd Yarax
./collect_binaries.sh
popd

dotnet build ./Yarax/Yarax.csproj -c Release
dotnet pack ./Yarax/Yarax.csproj -c Release -o ./nupkgs
