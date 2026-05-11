sudo docker run -d \
--log-driver none \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p $UDP2RAW_PUBLIC_PORT:$UDP2RAW_PUBLIC_PORT/tcp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name $CONTAINER_NAME \
$CONTAINER_NAME

sudo docker network connect amnezia-dns-net $CONTAINER_NAME
