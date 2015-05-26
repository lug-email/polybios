default: help

help:
	@echo "help   - display this text"
	@echo "build  - merge js libraries"
	@echo "watch  - build on file updated"

all: init build zip

.PHONY: build zip tests watch clean debug init

build: 
	cd public && rm -f polybios.zip && zip -r polybios.zip index.html css js img l10n manifest.webapp

watch:
	while true; do inotifywait -e close_write,moved_to,create,modify public/*; make build; done

