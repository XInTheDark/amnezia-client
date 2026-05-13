if sudo test -x /opt/amnezia/$CONTAINER_NAME/remove.sh; then sudo /opt/amnezia/$CONTAINER_NAME/remove.sh; fi;\
sudo docker stop $CONTAINER_NAME 2>/dev/null || true;\
sudo docker rm -fv $CONTAINER_NAME 2>/dev/null || true;\
sudo docker rmi $CONTAINER_NAME 2>/dev/null || true;\
sudo rm -rf /opt/amnezia/$CONTAINER_NAME
