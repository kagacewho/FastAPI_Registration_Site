import pytest
from fastapi.testclient import TestClient
from main import app, sessions, hash_password, USERS

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_and_teardown():
    sessions.clear()
    yield
    sessions.clear()

def test_get_login_page(): # Доступ к странице 
    response = client.get("/login")
    assert response.status_code == 200
    assert "<h2>Вход</h2>" in response.text

def test_login_success(): # Зашел
    response = client.post("/login", data={
        "username": "admin",
        "password": "1234"
    })
    assert response.status_code == 302
    assert response.headers["location"] == "/home/admin"
    assert len(sessions) == 1
    assert "session_id" in response.cookies

def test_login_fail_wrong_password(): # Не зашел
    response = client.post("/login", data={
        "username": "admin",
        "password": "wrong_password"
    })
    assert response.status_code == 200
    assert "Неверный пароль" in response.text
    assert len(sessions) == 0

def test_admin_page_access_denied_for_user(): # User не может попасть в home/admin
    client.post("/login", data={"username": "user1", "password": "4321"})
    response = client.get("/home/admin")
    assert response.status_code == 302
    assert response.headers["location"] == "/403"

def test_admin_page_access_granted_for_admin(): # Админ может попасть в home/admin
    client.post("/login", data={"username": "admin", "password": "1234"})
    response = client.get("/home/admin")
    assert response.status_code == 200
    assert "<h1>Регистрация</h1>" in response.text

def test_repeated_login(): # На повторный логин
    client.post("/login", data={"username": "user1", "password": "4321"})
    response = client.get("/login")
    assert response.status_code == 302
    assert response.headers["location"] == "/home/user1"