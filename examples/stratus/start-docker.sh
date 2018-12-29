docker run -it --rm --device /dev/fuse \
  -v /home/arnetheduck/status/nim-eth-p2p:/nim-eth-p2p:Z \
  -w /nim-eth-p2p/examples/stratus \
  --cap-add SYS_ADMIN \
  a12e/docker-qt:5.12-gcc_64 \
  sh build-in-docker.sh
