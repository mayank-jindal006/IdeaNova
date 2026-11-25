from __future__ import annotations

import logging
import shutil

from fastapi import APIRouter, Depends, HTTPException, status
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.ai.models import Finding
from app.schemas import ScanRepositoryRequest
from app.scanners.deps import scan_dependencies_with_status
from app.services.gitleaks import scan_repository_secrets
from app.auth import current_user, owned_repo
from app.db.models import User
from app.db.session import get_db
from app.github_client.client import clone_repo
from app.core.scan_paths import ScanPathError, ScanRootError, require_scan_root

router = APIRouter(prefix="/api/repositories", tags=["Repositories"])
logger = logging.getLogger(__name__)


@router.post("/scan", status_code=status.HTTP_200_OK, summary="Scan a repository for exposed secrets and known dependency vulnerabilities")
async def scan_repository_endpoint(payload: ScanRepositoryRequest, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    """Clone an owned GitHub repository into the trusted root and scan it."""
    repo_path: str | None = None
    try:
        repo = owned_repo(db, payload.repo_id, user)
        require_scan_root()
        repo_path = await run_in_threadpool(clone_repo, repo.full_name)
        secret_scan = await run_in_threadpool(scan_repository_secrets, repo_path)
        dependency_scan = await run_in_threadpool(scan_dependencies_with_status, repo_path)
        secrets = []
        for finding in secret_scan.findings:
            item = finding.redacted().model_dump(mode="json", exclude_none=True)
            item.update({"type": "secret", "scanner": secret_scan.source})
            secrets.append(item)
        dependencies = dependency_scan.findings
        findings = [*secrets, *dependencies]
        logger.info(
            "Repository scan completed secrets_status=%s secrets_source=%s dependencies_status=%s dependencies_queried=%s",
            secret_scan.status,
            secret_scan.source,
            dependency_scan.status,
            dependency_scan.dependencies_queried,
        )
        return {
            "repo_name": repo.full_name,
            "findings": findings,
            "count": len(findings),
            "scanners": {
                "secrets": {"status": secret_scan.status, "source": secret_scan.source, "reason": secret_scan.reason, "count": len(secrets)},
                "dependencies": {"status": dependency_scan.status, "source": "osv", "reason": dependency_scan.reason, "count": len(dependencies), "dependencies_queried": dependency_scan.dependencies_queried},
            },
        }
    except ScanRootError:
        raise HTTPException(status_code=503, detail="Repository scanning is unavailable") from None
    except ScanPathError:
        raise HTTPException(status_code=400, detail="Repository checkout is invalid") from None
    except FileNotFoundError:
        raise HTTPException(status_code=502, detail="Repository checkout is unavailable") from None
    except ValueError:
        raise HTTPException(status_code=400, detail="Repository checkout is invalid") from None
    except OSError:
        raise HTTPException(status_code=500, detail="Repository scan could not be completed") from None
    finally:
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)
