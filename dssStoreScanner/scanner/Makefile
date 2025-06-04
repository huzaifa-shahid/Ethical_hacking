# Makefile for .DS_Store Scanner

setup:
	@echo "[+] Running setup script..."
	chmod +x setup.sh
	./setup.sh

scan:
	@echo "[+] Running scanner on targets.txt..."
	python3 dsstore_scanner.py -i urls.txt --threads 5

single:
	@echo "[+] Running single URL scan..."
	python3 dsstore_scanner.py -u https://example.com/.DS_Store

clean:
	@echo "[+] Cleaning temporary files..."
	rm -f temp_dsstore
	rm -rf dsstore_scan_results
