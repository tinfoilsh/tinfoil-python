#!/bin/bash

rm -rf venv verifier tinfoil_verifier

python3 -m venv venv
source venv/bin/activate
pip3 install -e .

go install golang.org/x/tools/cmd/goimports@latest
go install github.com/go-python/gopy@latest

git clone --depth 1 -b v0.0.21 https://github.com/tinfoilsh/verifier

cd verifier || exit
gopy build -output=tinfoil_verifier -vm=python3 github.com/tinfoilsh/verifier/client
cd - || exit

mv verifier/tinfoil_verifier tinfoil_verifier
rm -rf verifier
