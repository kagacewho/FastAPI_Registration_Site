import uuid
import pandas as pd
import hashlib
import logging
import shutil
from pathlib import Path
from datetime import timedelta, datetime
from typing import Optional

from fastapi import FastAPI, Form, Request, Depends, HTTPException, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.status import HTTP_403_FORBIDDEN, HTTP_302_FOUND

logging.basicConfig(filename="logg", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads") 

templates = Jinja2Templates(directory="templates")

USERS = "users.csv"
SESSION_TTL = timedelta(minutes=3)
sessions = {}
white_urls = ["/", "/login", "/logout", "/403"]

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_session_data(request: Request) -> dict:
    session_id = request.cookies.get("session_id")
    if session_id not in sessions:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")

    session_data = sessions.get(session_id)
    if not session_data:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid session")

    if datetime.now() - session_data["created"] > SESSION_TTL:
        del sessions[session_id]
        logging.info(f"Session {session_id} expired during dependency check")
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Session expired")
    
    return session_data

def get_current_admin(session: dict = Depends(get_session_data)):
    if session.get("role") != "admin":
        logging.warning(f"User '{session.get('username')}' attempted admin access.")
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Admin access required")
    return session


@app.middleware("http")
async def check_session(request: Request, call_next):
    if request.url.path.startswith("/static") or \
       request.url.path.startswith("/uploads") or \
       request.url.path in white_urls:
        return await call_next(request)

    session_id = request.cookies.get("session_id")
    if session_id not in sessions:
        return RedirectResponse(url="/")

    session_data = sessions[session_id]
    if datetime.now() - session_data["created"] > SESSION_TTL:
        del sessions[session_id]
        logging.info(f"Session {session_id} expired")
        return RedirectResponse(url="/")

    sessions[session_id]["created"] = datetime.now()
    return await call_next(request)


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request, exc):
    if exc.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    
    if exc.status_code == 403:
        return RedirectResponse(url="/403", status_code=HTTP_302_FOUND)
        
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        username = sessions[session_id].get("username")
        if username:
            return RedirectResponse(url=f"/home/{username}", status_code=HTTP_302_FOUND)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        username_sess = sessions[session_id].get("username")
        return RedirectResponse(url=f"/home/{username_sess}", status_code=HTTP_302_FOUND)

    try:
        users = pd.read_csv(USERS)
    except FileNotFoundError:
        logging.error(f"{USERS} file not found.")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Ошибка сервера"})

    if username in users['users'].values:
        stored_hash = users[users['users'] == username]['password'].values[0]
        
        if hash_password(password) == stored_hash:
            session_id = str(uuid.uuid4())
            role = users[users['users'] == username]['role'].values[0]
            sessions[session_id] = {"created": datetime.now(), "username": username, "role": role}
            
            if role == "admin":
                redirect_url = "/home/admin"
            else:
                redirect_url = f"/home/{username}"

            response = RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)
            
            response.set_cookie("session_id", session_id, httponly=True)
            response.set_cookie("username", username, httponly=True)
            response.set_cookie("role", role, httponly=True)
            
            logging.info(f"User '{username}' logged in with role '{role}'")
            return response
        else:
            logging.warning(f"Failed login for '{username}': wrong password")
            return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный пароль"})
    
    logging.warning(f"Failed login attempt: unknown user '{username}'")
    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин"})


@app.post("/register")
def register(request: Request,
             username: str = Form(...),
             password: str = Form(...),
             role: str = Form(...),
             avatar: Optional[UploadFile] = File(None), 
             admin_data: dict = Depends(get_current_admin)):
    
    logging.info(f"Admin '{admin_data['username']}' processing registration for '{username}'")
    
    try:
        users = pd.read_csv(USERS)
        users.columns = users.columns.str.strip()
    except FileNotFoundError:
        users = pd.DataFrame(columns=["users", "password", "role", "avatar"])

    if username in users['users'].values:
        logging.warning(f"Registration failed: user '{username}' already exists")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Пользователь уже существует"
        })

    avatar_path = "uploads/default.png"

    if avatar and avatar.filename:
        suffix = Path(avatar.filename).suffix.lower()
        if suffix not in ['.png', '.jpg', '.jpeg', '.gif']:
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": "Недопустимый формат файла (только .png, .jpg, .gif)"
            })
        
        avatar_path = f"uploads/{username}{suffix}"
        
        try:
            with open(avatar_path, "wb") as buffer:
                shutil.copyfileobj(avatar.file, buffer)
            logging.info(f"Avatar saved for user '{username}' at '{avatar_path}'")
        except Exception as e:
            logging.error(f"Error saving avatar for '{username}': {e}")
            return templates.TemplateResponse("register.html", {
                "request": request, 
                "error": "Ошибка при сохранении файла аватара"
            })

    new_user = {
        "users": username,
        "password": hash_password(password),
        "role": role,
        "avatar": avatar_path
    }

    users = pd.concat([users, pd.DataFrame([new_user])], ignore_index=True)
    users.to_csv(USERS, index=False)
    
    logging.info(f"Admin '{admin_data['username']}' successfully registered user '{username}' with role '{role}'")
    return templates.TemplateResponse("register.html", {
        "request": request, 
        "message": f"Пользователь '{username}' успешно создан."
    })


@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        username = sessions[session_id].get("username", "unknown")
        del sessions[session_id]
        logging.info(f"User '{username}' logged out")
        
    response = RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    response.delete_cookie("session_id")
    response.delete_cookie("username")
    response.delete_cookie("role")
    return response

@app.get("/home/admin", response_class=HTMLResponse)
def get_admin_page(request: Request, 
                   admin_data: dict = Depends(get_current_admin)):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/home/{username}", response_class=HTMLResponse)
def get_user_home(request: Request, username: str, 
                  session: dict = Depends(get_session_data)):
    
    if session.get("username") != username:
        logging.warning(f"User '{session.get('username')}' tried to access '/home/{username}'")
        return RedirectResponse(url="/403", status_code=HTTP_302_FOUND)

    avatar_url = "uploads/default.png"
    try:
        users = pd.read_csv(USERS)
        user_row = users[users['users'] == username]
        
        if not user_row.empty:
            avatar_url = user_row['avatar'].values[0]
        else:
            logging.error(f"User '{username}' found in session but not in {USERS}")

    except FileNotFoundError:
        logging.error(f"{USERS} file not found in /home endpoint.")
    except KeyError:
        logging.warning(f"Column 'avatar' not found in {USERS}. Using default.")

    user_data = {
        "username": username,
        "avatar_url": f"/{avatar_url}" 
    }
    
    return templates.TemplateResponse("home.html", {"request": request, "user": user_data})

@app.get("/403", response_class=HTMLResponse)
def forbidden(request: Request):
    return templates.TemplateResponse("403.html", {"request": request})