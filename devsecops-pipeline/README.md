# PLI DevSecOps Pipeline

A containerized CI/CD pipeline with integrated security scanning, approval
gates, and compliance checking. All components are open source, run in
Docker containers, and report back to RiskDesk.

## Architecture

```
Developer → Gitea (git push) → Woodpecker CI
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              SonarQube        Trivy Agent      ZAP (DAST)
              (SAST)         (container/SCA/     (after staging
                              secret scan)        deploy)
                    │               │               │
                    └───────┬───────┘───────────────┘
                            ▼
                      Quality Gate
                    (no unreviewed criticals)
                            │
                            ▼
                    Manual Approval
                    (Woodpecker UI)
                            │
                            ▼
                    Production Deploy
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          RiskDesk      DefectDojo    OpenSCAP Agent
        (adjudication)  (aggregation) (CIS/STIG compliance)
```

## Components

| Service | Image | Purpose | Port |
|---|---|---|---|
| **Gitea** | gitea/gitea:1.22 | Self-hosted Git | 3000 |
| **Woodpecker** | woodpeckerci/woodpecker-server:v2 | CI/CD engine | 8000 |
| **SonarQube** | sonarqube:10-community | Static analysis (SAST) | 9090 |
| **OWASP ZAP** | zaproxy/zap-stable | Dynamic analysis (DAST) | 8090 |
| **DefectDojo** | defectdojo/defectdojo-django | Vulnerability aggregator | 8080 |
| **Trivy Agent** | custom (aquasec/trivy based) | Container, SCA, secret scanning | — |
| **OpenSCAP Agent** | custom (Ubuntu + openscap) | CIS/STIG compliance scanning | — |
| **PostgreSQL** | postgres:16-alpine | Shared database | — |
| **Redis** | redis:7-alpine | DefectDojo cache | — |

## Quick start

```bash
cp .env.example .env
# Edit .env with your passwords and the RiskDesk API token

docker compose up -d

# First-time setup:
# 1. Open Gitea at http://localhost:3000, create an admin account
# 2. Create an OAuth application in Gitea (Settings → Applications)
#    - Redirect URI: http://localhost:8000/authorize
# 3. Copy the Client ID and Secret into .env
# 4. Restart Woodpecker: docker compose restart woodpecker-server
# 5. Open Woodpecker at http://localhost:8000, log in via Gitea OAuth
# 6. Create a RiskDesk API token and put it in .env as RISKDESK_PIPELINE_TOKEN
```

## Pipeline stages

Copy `.woodpecker.yml` from `configs/woodpecker/` into each repository.
The pipeline runs:

1. **Build & test** — standard project build
2. **SonarQube SAST** — static code analysis
3. **Trivy dependency scan** — SCA with severity gate
4. **Secret detection** — fails on any detected secrets
5. **Container image scan** — Trivy on the built image
6. **Quality gate** — queries RiskDesk for unreviewed criticals; blocks deploy if any exist
7. **Deploy to staging** — if gates pass
8. **DAST scan** — ZAP baseline against the staging URL
9. **Manual approval** — maintainer must click "Approve" in Woodpecker
10. **Deploy to production** — after approval

## Scanning agents (requirement 5)

The Trivy and OpenSCAP agents run continuously as containers, not just
during CI. They scan on a schedule and report back to RiskDesk
automatically.

### Trivy Agent
- Scans all Docker images on the host via the mounted Docker socket
- Scans filesystem paths for dependency vulnerabilities
- Reports to both RiskDesk (via /api/pipeline/import) and DefectDojo
- Interval: TRIVY_SCAN_INTERVAL (default 1 hour)

### OpenSCAP Agent
- Evaluates CIS benchmarks and STIGs using the SCAP Security Guide
- Exports results as CIS-CAT-format CSV
- Uploads to RiskDesk's compliance import API
- Interval: OPENSCAP_SCAN_INTERVAL (default 24 hours)
- Configure profiles in openscap-agent/profiles.yml

## RiskDesk integration (requirements 6 & 7)

### Findings flow into RiskDesk
Pipeline scan results (Trivy, ZAP) are POSTed to `/api/pipeline/import`
using a bearer token. They appear in the Findings tab alongside Wiz,
Falcon, and GitHub findings with the same adjudication, scoring, and
risk decision behavior.

### Container management from RiskDesk
The Settings tab in RiskDesk shows all pipeline containers with their
status. Admins can start, stop, restart, and view logs directly from the
RiskDesk UI. Requires the Docker socket to be mounted into the RiskDesk
container.

### Quality gate queries RiskDesk
The Woodpecker pipeline's quality gate step queries RiskDesk's API for
unreviewed critical findings on the repository being deployed. If any
exist, the deploy is blocked. This means: the security team's
adjudication decisions in RiskDesk directly control what ships.

## Migration (requirement 4)

Everything is containerized. To move to a new host:

```bash
# On the old host:
docker compose down
tar czf pipeline-data.tar.gz \
  /var/lib/docker/volumes/devsecops-pipeline_*

# On the new host:
tar xzf pipeline-data.tar.gz -C /
docker compose up -d
```

Named volumes hold all state (Git repos, CI history, scan results,
databases). The compose file has no host-specific paths except the
Docker socket mount.

## Ticketing and approval gates (requirement 2)

Three gate mechanisms:

1. **Quality gate** (automated): the pipeline queries RiskDesk for
   unreviewed critical findings. If the security team hasn't adjudicated
   them, the deploy blocks. This is the "no unreviewed criticals"
   requirement.

2. **Manual approval** (Woodpecker): production deploys require a
   maintainer to click "Approve" in the Woodpecker UI. This is the
   human-in-the-loop gate.

3. **Exception workflow** (RiskDesk): teams can submit exception
   requests through RiskDesk. Approved exceptions create adjudication
   records that satisfy the quality gate — so the pipeline unblocks
   once the security team signs off, without anyone editing pipeline
   config.
