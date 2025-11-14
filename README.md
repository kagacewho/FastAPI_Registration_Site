# Fast_API

## Установка зависимостей и запуск uvicorn
python -m venv fastapi_venv 
.\fastapi_venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload

## Для https
openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes -new -x509
uvicorn main:app --reload --host 0.0.0.0 --port 8000 --ssl-keyfile key.pem --ssl-certfile cert.pem

## Уже для запуска используется ссылка с https
https://127.0.0.1:8000/

## Запуск тестов test_main.py
pytest