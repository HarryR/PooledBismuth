all:
	@echo Read README.md

clean:
	find . -name '*.pyc'  | xargs -n 1 rm