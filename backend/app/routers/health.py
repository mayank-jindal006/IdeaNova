from fastapi import APIRouter

router = APIRouter(tags=["System"])


@router.get("/health", summary="Service health check")
def health() -> dict[str, str]:
    return {"status": "ok"}
