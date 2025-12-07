#!/bin/bash
# run_all_pocs.sh
# Run all Proof of Concept scripts

echo "================================================================"
echo "PREMOGIFTCARDS BUG BOUNTY - PROOF OF CONCEPT RUNNER"
echo "================================================================"
echo ""

# Create evidence directory
mkdir -p evidence

# Check Python version
echo "[*] Checking Python version..."
python3 --version

# Install required packages if needed
echo "[*] Checking for required packages..."
pip3 install requests --quiet

echo ""
echo "========================================================================"
echo "1. RUNNING AZURE BLOB STORAGE POC (High Severity)"
echo "========================================================================"
python3 poc_azure_blob.py

echo ""
echo "========================================================================"
echo "2. RUNNING JWT TOKEN EXPOSURE POC (Medium Severity)"
echo "========================================================================"
python3 poc_jwt_exposure.py

echo ""
echo "========================================================================"
echo "3. RUNNING HEALTH ENDPOINT POC (Low Severity)"
echo "========================================================================"
python3 poc_health_endpoint.py

echo ""
echo "========================================================================"
echo "SUMMARY OF EVIDENCE COLLECTED"
echo "========================================================================"
echo ""

# Count evidence files
echo "[*] Evidence files collected:"
find evidence/ -type f | wc -l | xargs echo "  Total files:"
echo ""
echo "[*] Directory structure:"
tree evidence/ || ls -la evidence/

echo ""
echo "========================================================================"
echo "NEXT STEPS FOR BUG BOUNTY SUBMISSION"
echo "========================================================================"
echo ""
echo "1. Review the evidence in the 'evidence/' directory"
echo "2. Create screenshots if needed (recommended for visual proof)"
echo "3. Prepare submission on Bugcrowd:"
echo "   - Title: Clear, descriptive title for each finding"
echo "   - Target: Specify the vulnerable URL"
echo "   - Description: Copy from generated reports"
echo "   - Impact: Explain business consequences"
echo "   - Steps to reproduce: Use commands from POC scripts"
echo "   - Attach evidence files"
echo ""
echo "Submit in this order:"
echo "  1. Azure Blob Storage (High)"
echo "  2. JWT Token Exposure (Medium)"
echo "  3. Health Endpoint (Low/Informational)"
echo ""
echo "Good luck with your submission!"
