from fastapi import APIRouter, HTTPException, Depends, Body, Security, Header
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import APIKey
import secrets
import bcrypt

router = APIRouter()


def verify_api_key(provided_key: str, stored_hash: str):
    return bcrypt.checkpw(provided_key.encode(), stored_hash.encode())


def get_api_key(db: Session = Depends(get_db), x_api_key: str = Header(...)):
    db_key = db.query(APIKey).filter_by(is_admin=True).first()
    if db_key and verify_api_key(x_api_key, db_key.hashed_api_key):
        return db_key
    else:
        raise HTTPException(status_code=401, detail="Invalid API key")


def create_api_key(notes: str, is_admin: bool, db: Session):
    api_key = secrets.token_urlsafe(32)
    hashed_key = APIKey.hash_api_key(api_key)
    if db.query(APIKey).filter_by(hashed_api_key=hashed_key).first():
        raise HTTPException(status_code=400, detail="API key collision, please retry.")
    new_key = APIKey(hashed_api_key=hashed_key, notes=notes, is_admin=is_admin)
    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    return api_key, new_key.id


@router.post("/create", response_model=dict)
async def create_regular_api_key(
    notes: str = Body(default="", embed=True),
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(get_api_key),
):
    if not api_key.is_admin:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    api_key, api_key_id = create_api_key(notes, False, db)
    return {"message": "Regular API key created", "api_key": api_key, "id": api_key_id}


@router.post("/create/admin", response_model=dict)
async def create_admin_api_key(
    notes: str = Body(default="", embed=True),
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(get_api_key),
):
    if not api_key.is_admin:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    api_key, api_key_id = create_api_key(notes, True, db)
    return {"message": "Admin API key created", "api_key": api_key, "id": api_key_id}


@router.delete("/delete/{key_id}", status_code=204)
def delete_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(get_api_key),
):
    if not api_key.is_admin:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    delete_key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not delete_key:
        raise HTTPException(status_code=404, detail="API key not found to delete")
    db.delete(delete_key)
    db.commit()
    return {"message": "API key deleted successfully"}
