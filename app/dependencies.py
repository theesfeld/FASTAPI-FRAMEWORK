from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session
from .database import get_db
from .models import APIKey


async def get_api_key(db: Session = Depends(get_db), x_api_key: str = Header(...)):
    api_key_records = db.query(APIKey).all()
    for api_key_record in api_key_records:
        if api_key_record.verify_api_key(x_api_key):
            return api_key_record
    raise HTTPException(status_code=401, detail="Invalid API Key")


def get_current_user(api_key: str = Header(...), db: Session = Depends(get_db)):
    hashed_key = APIKey.hash_api_key(api_key)
    user = db.query(APIKey).filter(APIKey.hashed_api_key == hashed_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return user
