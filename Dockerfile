FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/
ENV PORT=8080
EXPOSE 8080
CMD ["sh","-c","exec python /app/server.py"]
