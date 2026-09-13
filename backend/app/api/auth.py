from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import create_access_token, verify_password
from app.db import get_db
from app.models import User
from app.schemas import LoginRequest, TokenResponse, UserResponse
from app.auth import get_current_user


router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    """
    Authenticate user and return JWT access token.
    """

    user = db.query(User).filter(
        User.email == payload.email
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    role_name = "VIEWER"

    if getattr(user, "role", None):
        if hasattr(user.role, "name"):
            role_name = user.role.name
        elif isinstance(user.role, str):
            role_name = user.role

    access_token = create_access_token(
        user_id=user.id,
        role=role_name,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user.id,
            email=user.email,
            role=role_name,
        ),
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def me(
    current_user: User = Depends(get_current_user),
):
    """
    Return the currently authenticated user.
    """

    role_name = "VIEWER"

    if getattr(current_user, "role", None):
        if hasattr(current_user.role, "name"):
            role_name = current_user.role.name
        elif isinstance(current_user.role, str):
            role_name = current_user.role

    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        role=role_name,
    )