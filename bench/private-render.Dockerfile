FROM python:3.12-alpine
COPY bench/private_storage.py /private_storage.py
COPY bench/private_render.py /private_render.py
ENTRYPOINT ["python3", "/private_render.py"]
