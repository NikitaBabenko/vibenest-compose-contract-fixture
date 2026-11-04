FROM python:3.12-alpine
COPY bench/render.py /render.py
ENTRYPOINT ["python3","/render.py"]
