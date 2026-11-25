FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/
EXPOSE 3000 8080
CMD ["python","/app/server.py"]
