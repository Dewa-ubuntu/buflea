sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9001
sudo iptables -t nat -I OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j REDIRECT --to-ports 9001
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9002
sudo iptables -t nat -I OUTPUT -p tcp -d 127.0.0.1 --dport 443 -j REDIRECT --to-ports 9002

