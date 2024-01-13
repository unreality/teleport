#!/bin/bash
cat >/etc/teleport.d/conf <<EOF
TELEPORT_ROLE=node
EC2_REGION=${region}
TELEPORT_AUTH_SERVER_LB=${auth_server_addr}
TELEPORT_CLUSTER_NAME=${cluster_name}
USE_ACM=${use_acm}
EOF
