PYTHON_FILES = `(find . -iname "*.py" -not -path "./.venv/*")`

clean:
	rm -rf .venv/

install: # Install project locally
	poetry install --sync

install-dev: # Install project locally with dev dependencies
	poetry install --sync --with dev

install-clean: clean install ## Clear and install dependencies

format: ## Format code using ruff format and cargo fmt
	poetry run ruff format $(PYTHON_FILES)

format-check: ## Check code format using ruff format and cargo fmt
	poetry run ruff format --check $(PYTHON_FILES)

lint: ## Run all linters with automated fix
	poetry run ruff --fix $(PYTHON_FILES)

lint-check: ## Run all linters
	poetry run ruff $(PYTHON_FILES)


help: ## Description of the Makefile commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'
