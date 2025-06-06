clean:
	rm -rf verifier tinfoil/tinfoil_verifier

bind:
	pip3 install .

	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/go-python/gopy@latest

	git clone --depth 1 -b v0.0.21 https://github.com/tinfoilsh/verifier

	cd verifier || exit
	gopy build -output=tinfoil_verifier -vm=python3 github.com/tinfoilsh/verifier/client
	cd - || exit

	mv verifier/tinfoil_verifier tinfoil/tinfoil_verifier
	rm -rf verifier

build:
	python3 -m build
