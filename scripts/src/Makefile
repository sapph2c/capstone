SOURCE = base.cpp

TARGETS = Evasive/APC-Injector-Monolithic/ \
          Evasive/APC-Injector/ \
          Evasive/PE-Injector-Monolithic/ \
          Evasive/PE-Injector/ \
          Evasive/DLL-Injector-Monolithic/ \
          Evasive/DLL-Injector/ \
          Simple/APC-Injector-Monolithic/ \
          Simple/APC-Injector/ \
          Simple/PE-Injector-Monolithic/ \
          Simple/PE-Injector/ \
          Simple/DLL-Injector-Monolithic/ \
          Simple/DLL-Injector/

# Generate action to run the generate script
generate:
	@echo "Running generate script with LHOST, HOSTNAME, LPORT..."
	@LHOST=$(LHOST) HOSTNAME=$(HOSTNAME) LPORT=$(LPORT) ./generate.sh
	@echo "Generate script executed successfully!"

# Copy the generated shellcode to the target directories
copy:
	@for dir in $(TARGETS); do \
		mkdir -p "$$dir"; \
		cp -v $(SOURCE) "$$dir"; \
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

