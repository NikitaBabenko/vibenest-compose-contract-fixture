FROM python:3.12-alpine
COPY bench/render.py /render.py
COPY bench/revision_render.py /revision_render.py
ENTRYPOINT ["python3","/render.py"]
