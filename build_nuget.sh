#/bin/bash

set -e

# Build the managed project and create a NuGet package
dotnet build ./Yarax.Managed/Yarax.Managed.csproj -c Release
dotnet pack ./Yarax.Managed/Yarax.Managed.csproj -c Release -o ./nupkgs

# Build the nuget package with all the native dependencies
pushd Yarax.Native
chmod +x collect_binaries.sh
./collect_binaries.sh
popd

dotnet build ./Yarax.Native/Yarax.Native.csproj -c Release
dotnet pack ./Yarax.Native/Yarax.Native.csproj -c Release -o ./nupkgs

# Finally, build the metapackage
dotnet build ./Yarax/Yarax.csproj -c Release
dotnet pack ./Yarax/Yarax.csproj -c Release -o ./nupkgs