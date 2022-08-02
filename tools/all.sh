#!/bin/zsh
echo -e "Compiling for anonymous ... "
cargo check --no-default-features --features=anonymous 2>cargo-output-anonymous.txt
if [[ $? -eq 0 ]] { rm cargo-output-anonymous.txt } else { echo "FAILED!" }

echo -e "Compiling for config_builder ... "
cargo check --no-default-features --features=config_builder 2>cargo-output-config_builder.txt
if [[ $? -eq 0 ]] { rm cargo-output-config_builder.txt } else { echo "FAILED!" }

echo -e "Compiling for cram-md5 ... "
cargo check --no-default-features --features=cram-md5 2>cargo-output-cram-md5.txt
if [[ $? -eq 0 ]] { rm cargo-output-cram-md5.txt } else { echo "FAILED!" }

echo -e "Compiling for default ... "
cargo check --no-default-features --features=default 2>cargo-output-default.txt
if [[ $? -eq 0 ]] { rm cargo-output-default.txt } else { echo "FAILED!" }

echo -e "Compiling for digest-md5 ... "
cargo check --no-default-features --features=digest-md5 2>cargo-output-digest-md5.txt
if [[ $? -eq 0 ]] { rm cargo-output-digest-md5.txt } else { echo "FAILED!" }

echo -e "Compiling for external ... "
cargo check --no-default-features --features=external 2>cargo-output-external.txt
if [[ $? -eq 0 ]] { rm cargo-output-external.txt } else { echo "FAILED!" }

echo -e "Compiling for login ... "
cargo check --no-default-features --features=login 2>cargo-output-login.txt
if [[ $? -eq 0 ]] { rm cargo-output-login.txt } else { echo "FAILED!" }

echo -e "Compiling for openid20 ... "
cargo check --no-default-features --features=openid20 2>cargo-output-openid20.txt
if [[ $? -eq 0 ]] { rm cargo-output-openid20.txt } else { echo "FAILED!" }

echo -e "Compiling for plain ... "
cargo check --no-default-features --features=plain 2>cargo-output-plain.txt
if [[ $? -eq 0 ]] { rm cargo-output-plain.txt } else { echo "FAILED!" }

echo -e "Compiling for provider ... "
cargo check --no-default-features --features=provider 2>cargo-output-provider.txt
if [[ $? -eq 0 ]] { rm cargo-output-provider.txt } else { echo "FAILED!" }

echo -e "Compiling for provider_base64 ... "
cargo check --no-default-features --features=provider_base64 2>cargo-output-provider_base64.txt
if [[ $? -eq 0 ]] { rm cargo-output-provider_base64.txt } else { echo "FAILED!" }

echo -e "Compiling for registry_static ... "
cargo check --no-default-features --features=registry_static 2>cargo-output-registry_static.txt
if [[ $? -eq 0 ]] { rm cargo-output-registry_static.txt } else { echo "FAILED!" }

echo -e "Compiling for saml20 ... "
cargo check --no-default-features --features=saml20 2>cargo-output-saml20.txt
if [[ $? -eq 0 ]] { rm cargo-output-saml20.txt } else { echo "FAILED!" }

echo -e "Compiling for scram-sha-1 ... "
cargo check --no-default-features --features=scram-sha-1 2>cargo-output-scram-sha-1.txt
if [[ $? -eq 0 ]] { rm cargo-output-scram-sha-1.txt } else { echo "FAILED!" }

echo -e "Compiling for scram-sha-2 ... "
cargo check --no-default-features --features=scram-sha-2 2>cargo-output-scram-sha-2.txt
if [[ $? -eq 0 ]] { rm cargo-output-scram-sha-2.txt } else { echo "FAILED!" }

echo -e "Compiling for securid ... "
cargo check --no-default-features --features=securid 2>cargo-output-securid.txt
if [[ $? -eq 0 ]] { rm cargo-output-securid.txt } else { echo "FAILED!" }

echo -e "Compiling for unstable_custom_mechanism ... "
cargo check --no-default-features --features=unstable_custom_mechanism 2>cargo-output-unstable_custom_mechanism.txt
if [[ $? -eq 0 ]] { rm cargo-output-unstable_custom_mechanism.txt } else { echo "FAILED!" }

echo -e "Compiling for testutils ... "
cargo check --no-default-features --features=testutils 2>cargo-output-testutils.txt
if [[ $? -eq 0 ]] { rm cargo-output-testutils.txt } else { echo "FAILED!" }
