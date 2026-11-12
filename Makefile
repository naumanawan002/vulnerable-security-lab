.PHONY: run test docker-up docker-down clean

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

test:
	pytest -v tests/

docker-up:
	docker compose up --build

docker-down:
	docker compose down

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
