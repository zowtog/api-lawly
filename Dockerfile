FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=8080 DATABASE_PATH=/data/licenses.db
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && groupadd --gid 10001 lawly && useradd --uid 10001 --gid lawly --no-create-home lawly && mkdir /data && chown lawly:lawly /data
COPY app.py ./
COPY static ./static
USER lawly
EXPOSE 8080
CMD ["python", "app.py"]
