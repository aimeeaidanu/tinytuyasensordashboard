FROM python:3.9
WORKDIR /app
RUN pip install --no-cache-dir tinytuya
RUN pip install --no-cache-dir firebase_admin
RUN pip install --no-cache-dir flask
COPY . .
CMD ["python", "server.py"]
EXPOSE 8888 
EXPOSE 6666/udp
EXPOSE 6667/udp