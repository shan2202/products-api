

docker build -t productapp:v1 .

docker run -d --name productappv1 -e ADMINPASSWORD="xxxx" -e JWT_SECRET="xxxx" -p 8000:8000 productapp:v1