import sys
sys.path.append("..")

from starlette.responses import RedirectResponse

from fastapi import Depends, HTTPException, status, APIRouter, Request, Response, Form
from pydantic import BaseModel
from typing import Optional
import models
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import jwt, JWTError

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import get_current_user, get_password_hash

templates = Jinja2Templates(directory="templates")

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={401: {"user": "Invalid user"}}
)


class NewPasswordForm():
    def __init__(self, request: Request):
        self.request: Request = request
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.new_password: Optional[str] = None


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


@router.get("/", response_class=HTMLResponse)
async def change_password(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        new_password: str = Form(...),
        db: Session = Depends(get_db)
):
    # user = await get_current_user(request)
    #
    # if user is None:
    #     return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    user = db.query(models.Users).filter(models.Users.username == username).first()
    hashed_password = get_password_hash(password)

    if user.hashed_password != hashed_password or user is None:
        msg = "Incorrect Username or Password"
        return templates.TemplateResponse("ui.html", {"request": request, "msg": msg})
    else:
        hashed_new_password = get_password_hash(new_password)
        user.hashed_password = hashed_new_password

    db.add(user)
    db.commit()

    msg = "Password successfully changed"
    return templates.TemplateResponse("ui.html", {"request": request, "msg": msg})
