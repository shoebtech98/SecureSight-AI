from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import User
from backend.app.core.rate_limit import rate_limit
from backend.app.schemas import (
    UserCreate, UserResponse, UserRegistrationResponse, UserLogin, Token,
    ForgotPasswordRequest, ResetPasswordRequest, UserUpdate, UserUpdateResponse,
    RecoveryCodeRotateRequest, RecoveryCodeRotateResponse,
)
from backend.app.core.security import (
    get_password_hash, verify_password, create_access_token,
    decode_access_token, REMEMBER_ME_ACCESS_TOKEN_EXPIRE_MINUTES,
    DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
    hash_security_answer, dummy_verify_password,
)
from datetime import timedelta
import logging
import secrets

# Module-level logger — output appears in the uvicorn terminal
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


bearer_scheme = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not credentials:
        raise credentials_exception
    
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise credentials_exception
        
    subject = payload.get("sub")
    version = payload.get("sv")
    # Legacy email-subject tokens are rejected. An email can be reassigned to
    # another account, whereas a numeric user ID cannot.
    if not isinstance(subject, str) or not subject.isdecimal() or not isinstance(version, int):
        raise credentials_exception

    user = db.query(User).filter(User.id == int(subject)).first()
    if user is None or user.session_version != version:
        raise credentials_exception
    return user


def _user_token(user: User, expires: timedelta | None = None) -> str:
    return create_access_token(
        data={"sub": str(user.id), "sv": user.session_version}, expires_delta=expires
    )

@router.post(
    "/register",
    response_model=UserRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("register", 10, 60))],
)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    logger.info("[Register] Request received for email: %s", user_in.email)

    # ── Step 1: Check email uniqueness ─────────────────────────────────
    try:
        existing_user = db.query(User).filter(User.email == user_in.email).first()
    except Exception:
        logger.exception("[Register] DB error while checking email uniqueness")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while checking email. Please try again."
        )

    if existing_user:
        logger.warning("[Register] Email already registered: %s", user_in.email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    logger.info("[Register] Email is unique, proceeding with account creation")

    # ── Step 2: Hash password ──────────────────────────────────────────
    try:
        hashed_password = get_password_hash(user_in.password)
        logger.info("[Register] Password hashed successfully")
    except Exception:
        logger.exception("[Register] Failed to hash password")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to secure the password. Please try again."
        )

    # ── Step 3: Build User model ───────────────────────────────────────
    recovery_code = secrets.token_urlsafe(32)
    new_user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed_password,
        security_question=user_in.security_question,
        security_answer=hash_security_answer(user_in.security_answer) if user_in.security_answer else "",
        recovery_code_hash=get_password_hash(recovery_code),
    )

    # ── Step 4: Persist to database ────────────────────────────────────
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(
            "[Register] User created successfully: id=%s email=%s",
            new_user.id, new_user.email
        )
    except Exception:
        db.rollback()
        logger.exception("[Register] DB error during user insert")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while creating the account. Please try again."
        )

    return {
        "id": new_user.id, "email": new_user.email, "full_name": new_user.full_name,
        "security_question": new_user.security_question,
        "created_at": new_user.created_at, "has_recovery_code": True,
        "recovery_code": recovery_code,
    }


@router.post(
    "/login",
    response_model=Token,
    dependencies=[Depends(rate_limit("login", 5, 60))],
)
def login(user_in: UserLogin, remember_me: bool = False, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_in.email).first()
    if not user:
        dummy_verify_password(user_in.password)
    if not user or not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Set expiration based on remember me
    if remember_me:
        expires = timedelta(minutes=REMEMBER_ME_ACCESS_TOKEN_EXPIRE_MINUTES)
    else:
        expires = timedelta(minutes=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
        
    access_token = _user_token(user, expires)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh", response_model=Token)
def refresh_token(current_user: User = Depends(get_current_user)):
    expires = timedelta(minutes=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = _user_token(current_user, expires)
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/forgot-password", dependencies=[Depends(rate_limit("forgot_password", 5, 60))])
def forgot_password(req: ForgotPasswordRequest):
    # The same response for every address avoids publishing account membership.
    return {"message": "If this account exists, use its saved recovery code to reset the password."}

@router.post("/reset-password", dependencies=[Depends(rate_limit("reset_password", 5, 60))])
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    invalid = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or recovery code",
    )
    if not user or not user.recovery_code_hash:
        dummy_verify_password(req.recovery_code)
        raise invalid
    code_hash = user.recovery_code_hash
    if not verify_password(req.recovery_code.strip(), code_hash):
        raise invalid
    # A conditional update consumes the code exactly once, including when two
    # reset requests race. It also invalidates every previously issued token.
    updated = db.query(User).filter(
        User.id == user.id, User.recovery_code_hash == code_hash
    ).update({
        User.hashed_password: get_password_hash(req.new_password),
        User.recovery_code_hash: None,
        User.session_version: User.session_version + 1,
    }, synchronize_session=False)
    if updated != 1:
        db.rollback()
        raise invalid
    db.commit()
    return {"message": "Password reset successful"}


@router.post("/recovery-code", response_model=RecoveryCodeRotateResponse)
def rotate_recovery_code(
    payload: RecoveryCodeRotateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    code = secrets.token_urlsafe(32)
    current_user.recovery_code_hash = get_password_hash(code)
    current_user.session_version += 1
    db.commit()
    db.refresh(current_user)
    return {"recovery_code": code, "access_token": _user_token(current_user)}

@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.put("/me", response_model=UserUpdateResponse)
def update_profile(profile_in: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Detect which sensitive fields are *actually* changing. Presence alone isn't
    # a change: the profile form always resends email and security_question, so
    # gating on presence would demand a password for a mere name edit.
    email_changed = bool(profile_in.email) and profile_in.email != current_user.email
    security_question_changed = (
        bool(profile_in.security_question) and profile_in.security_question != current_user.security_question
    )
    password_changed = bool(profile_in.password)
    security_answer_changed = bool(profile_in.security_answer)

    sensitive_change = password_changed or email_changed or security_question_changed or security_answer_changed

    # A valid session token alone must not be enough to take over the account
    # (change the password + recovery answer and lock the real owner out).
    # Re-authenticate with the current password before touching any credential
    # or recovery factor. Deliberately 400, not 401: the caller *is*
    # authenticated, and the client's response interceptor force-logs-out on 401,
    # which would eject the user on a simple typo.
    if sensitive_change:
        if not profile_in.current_password or not verify_password(profile_in.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect.",
            )

    if email_changed:
        # Check if email is already taken
        existing = db.query(User).filter(User.email == profile_in.email).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = profile_in.email

    if profile_in.full_name:
        current_user.full_name = profile_in.full_name

    if password_changed:
        current_user.hashed_password = get_password_hash(profile_in.password)

    if security_question_changed:
        current_user.security_question = profile_in.security_question

    if security_answer_changed:
        current_user.security_answer = hash_security_answer(profile_in.security_answer)

    if sensitive_change:
        current_user.session_version += 1

    db.commit()
    db.refresh(current_user)

    access_token = _user_token(current_user) if sensitive_change else None

    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "security_question": current_user.security_question,
        "created_at": current_user.created_at,
        "has_recovery_code": current_user.has_recovery_code,
        "access_token": access_token,
    }
