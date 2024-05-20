from fastapi import APIRouter, Depends
from ...dependencies import get_api_key
from .key_management import router as key_management_router

api_router = APIRouter(dependencies=[Depends(get_api_key)])
api_router.include_router(
    key_management_router, prefix="/keys", tags=["Key Management"]
)
