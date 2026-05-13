for d in /opt/amnezia/amnezia-udp2raw-wireguard /opt/amnezia/amnezia-udp2raw-awg; do if sudo test -x "$d/remove.sh"; then sudo "$d/remove.sh"; fi; done;\
sudo docker ps -a | grep amnezia | awk '{print $1}' | xargs sudo docker stop 2>/dev/null || true;\
sudo docker ps -a | grep amnezia | awk '{print $1}' | xargs sudo docker rm -fv 2>/dev/null || true;\
sudo docker images -a --format table | grep amnezia | awk '{print $3, $1 ":" $2}' | xargs sudo docker rmi 2>/dev/null || true;\
sudo docker network ls | grep amnezia-dns-net | awk '{print $1}' | xargs sudo docker network rm 2>/dev/null || true;\
sudo rm -frd /opt/amnezia
