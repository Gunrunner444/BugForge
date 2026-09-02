from fastapi import APIRouter

from app.api.v1.endpoints.analyses import router as analyses_router
from app.api.v1.endpoints.debugging import router as debugging_router
from app.api.v1.endpoints.projects import router as projects_router
from app.api.v1.endpoints.test_runs import router as test_runs_router

api_router = APIRouter()
api_router.include_router(projects_router)
api_router.include_router(analyses_router)
api_router.include_router(test_runs_router)
api_router.include_router(debugging_router)
