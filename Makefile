# ============================================================================
# PLI Security Platform — Makefile
# ============================================================================

VERSION := $(shell cat VERSION)

# --- RiskDesk ---------------------------------------------------------------

.PHONY: riskdesk-init riskdesk-serve riskdesk-demo riskdesk-test riskdesk-enrich

riskdesk-init:
	cd riskdesk && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
	cd riskdesk && .venv/bin/python -m app.cli init

riskdesk-serve:
	cd riskdesk && .venv/bin/python -m app.cli serve

riskdesk-demo:
	cd riskdesk && .venv/bin/python -m app.cli demo

riskdesk-test:
	cd riskdesk && .venv/bin/python -c "\
		from app.db import init_db, SessionLocal; \
		from app.auth import seed_default_users; \
		init_db(); db = SessionLocal(); seed_default_users(db); \
		from app.sync import run_sync; \
		run_sync('falcon', demo=True, actor='test'); \
		from app.compliance import parse_file; \
		print('Core modules OK'); db.close()"

riskdesk-enrich:
	cd riskdesk && .venv/bin/python -c "\
		from app.enrichment import enrich_all; \
		from app.db import SessionLocal; \
		db = SessionLocal(); print(enrich_all(db)); db.close()"

riskdesk-expire:
	cd riskdesk && .venv/bin/python -m app.cli expire

# --- Pipeline ---------------------------------------------------------------

.PHONY: pipeline-up pipeline-down pipeline-status pipeline-logs pipeline-build

pipeline-up:
	cd devsecops-pipeline && docker compose up -d

pipeline-down:
	cd devsecops-pipeline && docker compose down

pipeline-status:
	cd devsecops-pipeline && docker compose ps

pipeline-logs:
	cd devsecops-pipeline && docker compose logs --tail=50

pipeline-build:
	cd devsecops-pipeline && docker compose build

# --- Packaging --------------------------------------------------------------

.PHONY: package clean

package:
	@echo "Packaging v$(VERSION)..."
	cd riskdesk && find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf riskdesk/data riskdesk/.venv
	zip -qr pli-security-$(VERSION).zip \
		riskdesk/ devsecops-pipeline/ deploy.sh README.md \
		CHANGELOG.md VERSION Makefile .gitignore \
		-x "**/__pycache__/*" "**/.venv/*" "**/data/*" "**/.env"
	@echo "Built pli-security-$(VERSION).zip"

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf riskdesk/data riskdesk/.venv
	rm -f *.zip

# --- Deployment -------------------------------------------------------------

.PHONY: deploy status

deploy:
	sudo ./deploy.sh

status:
	@/opt/pli-security/scripts/status.sh 2>/dev/null || echo "Not deployed. Run 'make deploy' first."
