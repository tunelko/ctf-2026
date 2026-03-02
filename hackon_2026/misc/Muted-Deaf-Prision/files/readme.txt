sudo docker rm -f my-extreme-challenge-2
sudo docker build -t extreme-jail-2 .
sudo docker run -d --privileged -p 1337:1337 --name my-extreme-challenge-2 extreme-jail-2
